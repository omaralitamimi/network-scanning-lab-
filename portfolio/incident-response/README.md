# SOC Case Study: Failures Followed by Successful Sign-In

**Fictional tabletop exercise. AI-assisted. No real compromise, production deployment or containment action is claimed.** Evidence comes from the adjacent SQL lab. This is a writing and decision-making exercise, not proof that Omar handled a live incident.

## Executive summary
Synthetic sign-in E04 follows three failed attempts for lab-user from the same source IP within three minutes. The correlation merits investigation. Available evidence does not establish compromise. Proposed initial priority: medium, pending asset sensitivity and identity validation.

## Scope and evidence
Source: `../sql-investigation/schema.sql`, six synthetic login records, UTC. Every address is a documentation address. The evidence covers only authentication and a partial asset list; no endpoint, MFA, mail or network telemetry was supplied.

| UTC on 2026-01-01 | Evidence | Observation |
|---|---|---|
| 10:00 | E01 | Failed sign-in, lab-user, 198.51.100.20 |
| 10:01 | E02 | Second failed sign-in, same user and source |
| 10:02 | E03 | Third failed sign-in, same user and source |
| 10:03 | E04 | Successful sign-in, same user and source |
| 10:04 | E05 | Separate successful sign-in by benign-user |
| 10:05 | E06 | Failed sign-in by benign-user; not part of the E04 sequence |

## Competing hypotheses
- Legitimate user corrected a mistyped or stale password. Validate with the user over a known contact route and compare usual device/MFA context.
- Unauthorized actor obtained valid credentials. Seek new-device activity, MFA changes, unusual session use and post-login access.
- Shared proxy/NAT or test activity produced the sequence. Check approved testing schedules and network ownership.

## Investigation plan
1. Preserve original events, collection times, event IDs and time-zone normalization; record evidence access and integrity hashes when collecting real files.
2. Validate account sensitivity, usual sign-in patterns, device identity, MFA outcome and authorized VPN egress.
3. Review session actions after 10:03, endpoint alerts and privileged changes. Expand the window and related accounts if justified.
4. Document missing telemetry. Escalate to the incident lead when evidence supports unauthorized access, sensitive actions or ongoing activity.

## Proposed response (not executed)
If unauthorized access is confirmed, request the authorized owner to revoke affected sessions, reset credentials through the approved process and review MFA enrollment. Isolate a device only when endpoint evidence and operational impact justify it. Avoid blindly blocking shared IPs. Preserve relevant evidence before disruptive changes where feasible.

Recovery requires identity verification, secure access restoration and monitoring for recurrence. Close as benign only with documented corroboration; otherwise retain an unresolved disposition and owner. Record who approved and performed each action.

## Current disposition
**Unresolved training scenario.** Login correlation alone cannot distinguish a legitimate retry from compromise. No containment, password reset or incident closure was performed.

## Lessons and deliverables
The SQL result is reproducible evidence of a correlation, not a verdict. A useful SOC note separates facts, hypotheses, missing data and proposed actions. See `case-note-template.md` for a reusable case note.
