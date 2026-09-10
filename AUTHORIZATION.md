# AUTHORIZATION.md

This document defines what is authorized in this lab. It is the single source of truth for scope. Anything not listed here is NOT authorized.

## 1. Authorized targets (exhaustive)

1. **First-party code in this repository** (`vulnerable-app/`, `lab/`), executed on the researcher's own machine or local containers.
2. **Deliberately-vulnerable applications run locally** (this repo's demo app; optionally OWASP Juice Shop via local Docker — only a local instance started by the researcher).
3. **Educational labs/CTFs** (e.g. PortSwigger Web Security Academy, HackTheBox, TryHackMe) — ONLY within the provider's Terms of Service and lab scope. Provider rules override this document where stricter.
4. **Bug bounty programs** — ONLY targets explicitly in scope, ONLY methods the program allows. No program active at this time; this line will be updated with program name + scope URL before any such work begins.

## 2. Explicitly prohibited

- Testing, scanning, probing, or accessing any system the researcher does not own and has no written authorization for.
- Social engineering, phishing, credential stuffing, or attacks on real users/data.
- Exfiltration, persistence, lateral movement, or any activity outside the vulnerable-app container.
- Using findings from this lab against any third party.
- Representing lab findings as real-world breaches, CVEs, or paid engagements.

## 3. Environment controls

- Demo app binds to `127.0.0.1` only; never `0.0.0.0` except inside the Compose isolated network.
- No production data. Seed data is fictional (`alice`, `bob` test users).
- Secrets: none. Test credentials are documented in code and worthless outside localhost.
- Network egress: none required. Tests run offline.

## 4. How authorization is evidenced

- This file (scope) + git history (who changed what, when).
- `docs/scope.md` (target inventory with ownership).
- Each write-up's "Authorized reproduction" section names the exact target instance (e.g. "local Flask on 127.0.0.1:5000, commit <sha>").
- CI runs tests only against the local app fixture — no external hosts appear in any config.

## 5. Use of results

Results are used exclusively for: remediation patches in this repo, regression tests, defensive documentation, and learning notes. No offensive tooling is published. Proof-of-concept code is the minimum necessary to demonstrate the flaw and verify the fix.

## 6. Change control

Any new target class requires an update to this file + `docs/scope.md` BEFORE testing begins, committed to git. Undocumented targets are out of scope by default.

*Last reviewed: 2026-09-10. Owner: repository maintainer (individual researcher).*
