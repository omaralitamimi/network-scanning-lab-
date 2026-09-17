"""Offline email triage. Never fetch URLs, execute content or open attachments."""
import argparse
import hashlib
import json
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []
    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'a':
            self.urls.extend(v for k, v in attrs if k.lower() == 'href' and v)

def domains(values):
    return sorted({address.rsplit('@', 1)[1].lower() for _, address in getaddresses(values) if '@' in address})

def analyze(raw):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    sender = domains(msg.get_all('From', []))
    reply = domains(msg.get_all('Reply-To', []))
    urls, attachments, flags = set(), [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b''
        name = part.get_filename()
        if name or part.get_content_disposition() == 'attachment':
            attachments.append({'filename': name, 'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()})
            continue
        if part.get_content_type() not in ('text/plain', 'text/html'):
            continue
        charset = part.get_content_charset() or 'utf-8'
        try:
            body = payload.decode(charset, errors='replace')
        except LookupError:
            body = payload.decode('utf-8', errors='replace')
        if part.get_content_type() == 'text/html':
            parser = Links()
            parser.feed(body)
            urls.update(parser.urls)
        else:
            urls.update(re.findall(r'https?://[^\s<>"\']+', body))
    hosts = set()
    malformed = 0
    for url in urls:
        try:
            parsed = urlsplit(url)
            if parsed.scheme.lower() in ('http', 'https') and parsed.hostname:
                hosts.add(parsed.hostname.lower())
        except ValueError:
            malformed += 1
    if sender and reply and set(sender) != set(reply):
        flags.append('From and Reply-To domains differ; verify legitimate routing before escalating.')
    if attachments:
        flags.append('Attachments present; hashes are inventory only, not malware verdicts.')
    return {'subject': str(msg.get('Subject', '')), 'from_domains': sender, 'reply_to_domains': reply,
            'url_hosts': sorted(hosts), 'malformed_urls': malformed, 'attachments': attachments,
            'authentication_results_untrusted': [str(v) for v in msg.get_all('Authentication-Results', [])],
            'review_flags': flags, 'verdict': 'manual_review_required'}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('eml', type=Path)
    args = parser.parse_args()
    if args.eml.stat().st_size > 10 * 1024 * 1024:
        parser.error('Input exceeds the 10 MiB demonstration limit.')
    print(json.dumps(analyze(args.eml.read_bytes()), indent=2))
