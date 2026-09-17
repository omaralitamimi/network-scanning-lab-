# SQL Authentication Investigation

AI-assisted synthetic investigation using SQLite. Demonstrates JOIN, GROUP BY, HAVING, time-window correlation and asset enrichment without deploying a SIEM.

## Run (from repository root)
```bash
python3 portfolio/sql-investigation/run.py
```
Python 3.10+; no dependencies or persistent database. The script builds only the bundled synthetic data in memory; it is not a general real-log importer.

## Question
Which successful sign-ins were preceded by at least three failed attempts for the same user and source IP during the previous ten minutes?

`schema.sql` defines six fictional events and a small asset inventory. `query.sql` correlates them. Expected result: E04, lab-user, 198.51.100.20, three preceding failures. E05 is excluded. All addresses use documentation ranges.

## Interpretation
The match is a triage lead. It could reflect password guessing, a user correcting a password, shared NAT or a test. An address missing from this tiny inventory is not evidence of an attacker. Validate identity, MFA records, VPN/NAT context and downstream actions before classifying the incident.

## Limits and tuning
The threshold is illustrative. Source events must be normalized, valid UTC and uniquely identified before use. The lower window boundary is inclusive; the success time is exclusive. Shared addresses, distributed attacks, missing logs and repeated success events affect results. This query is SQLite SQL and must be adapted and tested before use in a SIEM.

## Practice
Change the threshold, add a failure exactly ten minutes before the success, and add one from a different IP. Explain why each does or does not change the result. See `../incident-response/` for the related fictional case.
