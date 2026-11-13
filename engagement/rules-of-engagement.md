# Rules of engagement — template

**Engagement:** [name / reference]  **Version:** [n]  **Date:** [YYYY-MM-DD]

## 1. Parties

| Role | Name | Organization | Contact |
| --- | --- | --- | --- |
| System owner (authorizer) | [ ] | [ ] | [ ] |
| Technical contact | [ ] | [ ] | [ ] |
| Emergency contact (24h) | [ ] | [ ] | [phone] |
| Assessor | [ ] | [ ] | [ ] |

## 2. Authorization

[System owner] confirms it owns or is legally entitled to authorize testing of
every target in §3 and authorizes [assessor] to perform the activities in §5
against those targets during the window in §4. Where a target is operated by a
third party, the owner attaches that party's written permission or testing policy.

Anything not listed in §3 is out of scope. Testing does not start until this
document is signed by both parties.

## 3. Scope

| # | Target (URL / host / repository) | Environment | Owner | Notes |
| --- | --- | --- | --- | --- |
| 1 | [ ] | [prod / staging] | [ ] | [ ] |

**Explicitly out of scope:** [hosts, paths, tenants, third-party services].

## 4. Schedule

Window: [start] to [end], [time zone]. Permitted hours: [ ]. Blackout periods: [ ].

## 5. Permitted and prohibited activities

| Activity | Permitted | Condition |
| --- | --- | --- |
| Manual and automated vulnerability testing of in-scope targets | [yes/no] | [rate limit] |
| Exploitation to confirm impact | [yes/no] | Minimum necessary; stop at proof |
| Access to data beyond test accounts | [yes/no] | Record existence only; do not copy |
| Modification or deletion of data | [yes/no] | Test accounts only unless approved per case |
| Denial-of-service or load testing | no | Unless separately agreed in writing |
| Social engineering, phishing, physical access | no | Unless separately agreed in writing |
| Persistence, lateral movement beyond scope, malware | no | — |
| Testing of third-party or shared infrastructure | no | Unless the third party authorizes it |

## 6. AI-assisted testing

| Item | Agreed value |
| --- | --- |
| AI models may be used to analyse target material | [yes/no] |
| Providers permitted | [ ] |
| Material that may be sent (source, responses, logs) | [ ] |
| Material that must never be sent | Production secrets, personal data, [ ] |
| Provider-side data retention accepted | [yes/no] — some vetted-access programs require it |
| Autonomous actions against targets | Not permitted; a human reviews and issues every action |

## 7. Data handling

- Collect the minimum evidence needed to prove each finding; mask personal data
  and secrets in screenshots and logs.
- Store engagement data encrypted, on devices and accounts meeting the
  [operating standard](operating-standard.md).
- Retain until [date / N days after final report], then delete and confirm
  deletion in writing.
- Report any suspected exposure of client data to the emergency contact within
  24 hours.

## 8. Communication and escalation

- Status updates: [frequency, channel].
- A finding rated critical, or any sign of prior compromise by another party, is
  reported to the technical contact immediately and testing of that component
  pauses until the client responds.
- **Stop condition:** either party may halt testing at any time by contacting
  the other party's emergency contact. Testing also halts on any unexpected
  service degradation.

## 9. Deliverables

Report with executive summary, findings (root cause, reproduction, impact, CVSS
vector and score, remediation), retest results and, where agreed, detection
rules. Delivered by [date] through [channel]. Findings remain confidential to
the client unless the client agrees otherwise in writing.

## 10. Signatures

| System owner | Assessor |
| --- | --- |
| Name: [ ] | Name: [ ] |
| Date: [ ] | Date: [ ] |
| Signature: [ ] | Signature: [ ] |
