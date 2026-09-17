import importlib.util
import sqlite3
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
email = load('email_triage', ROOT / 'email-triage/triage.py')
sql = load('sql_lab', ROOT / 'sql-investigation/run.py')
class EmailTests(unittest.TestCase):
    def test_sample(self):
        result = email.analyze((ROOT / 'email-triage/sample.eml').read_bytes())
        self.assertEqual(result['url_hosts'], ['example.net'])
        self.assertEqual(len(result['attachments']), 1)
        self.assertEqual(len(result['review_flags']), 2)
        self.assertEqual(result['verdict'], 'manual_review_required')
    def test_matching_domains_not_safe_verdict(self):
        result = email.analyze(b'From: a@example.com\nReply-To: b@example.com\n\nHello')
        self.assertEqual(result['review_flags'], [])
        self.assertEqual(result['verdict'], 'manual_review_required')
    def test_malformed_url_and_unknown_charset(self):
        raw = b'Content-Type: text/html; charset=unknown-charset\n\n<a href="http://[bad">test</a>'
        self.assertEqual(email.analyze(raw)['malformed_urls'], 1)
    def test_no_headers(self):
        self.assertEqual(email.analyze(b'hello')['from_domains'], [])
class SQLTests(unittest.TestCase):
    def test_fixture(self):
        result = sql.investigate()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['success_event'], 'E04')
        self.assertEqual(result[0]['preceding_failures'], 3)
    def test_time_boundaries_and_identity(self):
        with sqlite3.connect(':memory:') as db:
            db.executescript((ROOT / 'sql-investigation/schema.sql').read_text())
            db.execute('DELETE FROM login_events')
            rows = [
                ('s','2026-01-01T10:10:00Z','u','192.0.2.1','success'),
                ('a','2026-01-01T10:00:00Z','u','192.0.2.1','failure'),
                ('b','2026-01-01T10:01:00Z','u','192.0.2.1','failure'),
                ('c','2026-01-01T10:02:00Z','u','192.0.2.1','failure'),
                ('old','2026-01-01T09:59:59Z','u','192.0.2.1','failure'),
                ('same','2026-01-01T10:10:00Z','u','192.0.2.1','failure'),
                ('ip','2026-01-01T10:03:00Z','u','192.0.2.2','failure'),
                ('user','2026-01-01T10:03:00Z','v','192.0.2.1','failure')]
            db.executemany('INSERT INTO login_events VALUES (?,?,?,?,?)', rows)
            result = db.execute((ROOT / 'sql-investigation/query.sql').read_text()).fetchall()
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0][4], 3)
            db.execute("DELETE FROM login_events WHERE event_id='a'")
            self.assertEqual(db.execute((ROOT / 'sql-investigation/query.sql').read_text()).fetchall(), [])
