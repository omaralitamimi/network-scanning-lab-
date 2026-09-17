# Offline Email Triage

AI-assisted learning project. The supplied email and identities are synthetic; reserved example domains are used. No message is sent, no URL is visited and no attachment is written or executed.

## Run (from repository root)
```bash
python3 portfolio/email-triage/triage.py portfolio/email-triage/sample.eml
```
Compare with `expected.json`. Python 3.10+; standard library only.

## Analyst workflow
1. Preserve the original message and record the source and collection time privately.
2. Compare From/Reply-To domains, review URL hosts and inventory attachment hashes.
3. Establish the receiving mail gateway's trusted Authentication-Results boundary before using SPF/DKIM/DMARC findings. The script returns that header as **untrusted text**; the sender can forge it.
4. Ask whether the message was expected and whether any user clicked, entered credentials or opened a file. Use approved tooling for deeper analysis.
5. Record evidence, uncertainty, proposed action and escalation owner.

The fixture has different From/Reply-To domains, one URL host and one harmless text attachment. Those observations justify review, not a malicious verdict. Legitimate mailing services can have different reply domains; matching domains also do not prove safety.

## Limits
This is an inventory tool, not a spam filter, malware scanner or authentication verifier. It does not validate DNS, reputation, display-text deception, redirects or all MIME encodings. Nested attached messages and unusual malformed MIME may require manual review. The CLI limits input to 10 MiB; returned JSON may contain sensitive subjects or filenames when using real mail. Publish only sanitized fixtures.

## Explain in an interview
Why is a hash not a malware verdict? Who is allowed to assert Authentication-Results? What additional evidence would justify containment?
