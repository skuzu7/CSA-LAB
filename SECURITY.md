# SECURITY.md

## Supported versions

This is a research lab, not production software. The demo app under `vulnerable-app/` is INTENTIONALLY VULNERABLE — do not deploy it, do not expose it to any network. Security fixes land as `remediation/FINDING-*/` patches with regression tests.

| Component | Status |
|---|---|
| `vulnerable-app/` (demo target) | intentionally vulnerable by design |
| `remediation/` patches | maintained, tested |
| `lab/` compose | localhost-only |

## Reporting a vulnerability

Found a REAL issue (not one of the planted demo flaws)? Email: **[NECESSÁRIO DO USUÁRIO — security contact email]**.

Please include: affected file/commit, steps to reproduce locally, impact assessment, suggested fix. Allow up to 7 days for triage. Do not publish before coordinated disclosure completes.

Note: the three documented findings (001–003) are planted lab exercises. Reporting them is unnecessary — their write-ups already contain the fix.

## Scope

In scope: this repository's code and docs. Out of scope: any system running this code outside localhost, any third party, social engineering, DoS testing.

## Disclosure policy

- Coordinated disclosure, 90-day default for real issues in lab tooling.
- Demo flaws: fully public by design (they only affect the local demo).
- No bounties offered (individual research project).

## Data protection

No personal data is processed. All fixtures are synthetic. Test traffic never leaves the machine.
