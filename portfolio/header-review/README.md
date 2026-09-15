# HTTP Security Header Review

Review a saved final HTTPS response header block offline. No requests are made to websites.

```bash
python3 portfolio/analyze.py headers portfolio/header-review/headers.txt
```

The synthetic sample has `nosniff` and a Referrer-Policy, but lacks CSP, HSTS and Permissions-Policy. See `expected.json` for the generated review.

## Interpretation
Missing headers are hardening review items, not confirmed exploitable vulnerabilities. Header presence alone does not establish a secure configuration. Review CSP directives, HSTS deployment and browser-feature requirements in application context. This tool does not prevent or test XSS.

## Input and limitations
Supply one final response header block, not multiple redirects. Header names are case-insensitive; values are retained for manual review. Cookies, HTML, TLS, CSP directive effectiveness and browser behavior are outside scope.

## Interview walkthrough
Explain why a permissive CSP can be ineffective, why HTTPS matters for HSTS, and why output encoding remains necessary for XSS prevention.
