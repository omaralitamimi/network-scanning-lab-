# Authentication Event Triage

Offline Python exercise for identifying repeated failed logins in a rolling time window.

## Run
From the repository root:
```bash
python3 portfolio/analyze.py auth portfolio/auth-triage/events.csv --threshold 3 --window-minutes 5
```

## Evidence and interpretation
All input events are synthetic, using documentation IP addresses. The sample produces one alert for 192.0.2.25 at 10:02 UTC with three failures involving alice and bob. A successful login from a different IP does not count toward the threshold. See `expected.json` for actual generated output.

## Analyst follow-up
Check whether the source is an approved gateway, correlate MFA and successful login events, establish account ownership, and compare activity with the normal baseline. Escalate with timestamps and evidence if suspicious. Do not disable accounts solely from this finding.

## Limitations
This is a teaching rule, not a production detector. Shared NAT, forgotten passwords and automated clients can cause false positives. Slow attempts and distributed attacks may evade the per-IP threshold. Repeated overlapping alerts are retained deliberately for transparency; no deduplication or SIEM integration is implemented. Input must use the documented normalized CSV schema and timezone-aware ISO timestamps.

## Interview walkthrough
Explain the inclusive five-minute boundary, source grouping, out-of-order input handling, false positives, and the evidence needed before concluding compromise.
