# Sample security assessment report

> **Sample deliverable.** The target is this repository's own intentionally
> vulnerable fixture, tested on loopback with synthetic data. It shows the format,
> depth and evidence standard of a client report. It is not a report on any
> third-party system and does not describe a paid engagement.

| | |
| --- | --- |
| Target | "Notes & Ledger" demo service (`vulnerable-app/`), HTTP API, 9 routes |
| Assessment type | White-box web/API security assessment with remediation retest |
| Assessor | [@skuzu7](https://github.com/skuzu7) |
| Authorization | [AUTHORIZATION.md](../AUTHORIZATION.md) §1.1 — first-party code, local instance |
| Dates | Findings documented 2026-09-10; retest and detection validation 2026-11-13 |
| Report version | 1.0 — public sample |

## 1. Executive summary

The service could be fully compromised by an unauthenticated user. Six
weaknesses were confirmed; chained together they let an outsider read the
application's source code, impersonate any user, read every user's notes, reach
internal-only configuration and move funds between accounts.

All six are fixed in the remediated build. Each fix is covered by a regression
test that also proves the legitimate feature still works, and each attack is
covered by a detection rule that fires whether or not the attack succeeds.

| Severity (CVSS v3.1) | Confirmed | Remediated | Retest |
| --- | ---: | ---: | --- |
| High (7.0–8.9) | 5 | 5 | Pass |
| Medium (4.0–6.9) | 1 | 1 | Pass |
| **Total** | **6** | **6** | **6 / 6 pass** |

**Recommended next step for a real system of this shape:** deploy the six fixes
together (they are small and independent), then load the detection rules so that
continued probing is visible.

## 2. Scope and method

- **In scope:** all HTTP routes of the fixture on `127.0.0.1:5000`. **Out of
  scope:** everything else ([scope inventory](../docs/scope.md)).
- **Approach:** source-assisted manual testing following the
  discover → validate → remediate → regression-test → document loop in
  [methodology.md](../docs/methodology.md). No automated scanners were used.
- **Proof standard:** every finding has a minimal automated proof of concept, a
  root-cause statement tied to a line of code, a patch and a regression test.
- **Scoring:** CVSS v3.1 base scores computed from vectors
  ([classification.md](../docs/classification.md)), rated as if the service were
  internet-reachable. On loopback with synthetic data the real risk is nil.

## 3. Findings summary

| ID | Finding | CWE | CVSS | Severity | Status |
| --- | --- | --- | ---: | --- | --- |
| [006](../writeups/finding-006.md) | Server-side request forgery in URL preview | CWE-918 | 8.6 | High | Fixed, retested |
| [002](../writeups/finding-002.md) | SQL injection in search | CWE-89 | 7.5 | High | Fixed, retested |
| [003](../writeups/finding-003.md) | Path traversal in file download | CWE-22 | 7.5 | High | Fixed, retested |
| [004](../writeups/finding-004.md) | Forgeable session token | CWE-287 | 7.5 | High | Fixed, retested |
| [005](../writeups/finding-005.md) | Negative-amount transfer | CWE-839 | 7.5 | High | Fixed, retested |
| [001](../writeups/finding-001.md) | Missing object ownership check (IDOR) | CWE-639 | 6.5 | Medium | Fixed, retested |

## 4. Attack path

1. **Read the source.** `GET /download?f=../app.py` returns the application
   code (003). The code shows that a session token is the user name in base64.
2. **Become any user.** A locally built token for `bob` is accepted by
   `GET /me` (004). No password or secret is needed.
3. **Read everything.** `GET /note/3` returns another user's note because
   ownership is never checked (001); the search endpoint returns all rows when
   the filter is closed with a quote (002).
4. **Reach the inside.** `GET /preview?url=…/internal/config` makes the server
   fetch an internal-only route and return its secret (006). On a cloud host the
   same request shape reaches the instance metadata service.
5. **Move money.** `POST /transfer` with `amount: -50` pulls funds from the
   destination account (005).

The full step-by-step plan with ATT&CK mapping is in
[adversary-emulation-plan.md](../docs/adversary-emulation-plan.md).

## 5. Findings in brief

Full write-ups (context, root cause, reproduction, patch, residual risk) are
linked from the IDs above.

| ID | Root cause | Fix applied | Residual risk to track |
| --- | --- | --- | --- |
| 006 | Raw user URL passed to `urlopen` | Parse, then allowlist scheme, host and path before fetching | Allowlists do not stop DNS rebinding; resolve and pin the address for public fetchers |
| 002 | User input interpolated into SQL | Bound parameter in the `LIKE` clause | None for this sink; review every other query the same way |
| 003 | User path joined without containment | Resolve the path and require it to stay inside `files/` | Symlinks inside the served directory |
| 004 | Token is unsigned, client-forgeable | HMAC-SHA256 signature, constant-time comparison | Fixture key lives in source; real keys belong in a secret manager, with expiry and rotation |
| 005 | Amount not validated | Integer type, positive, upper bound, distinct accounts | The endpoint still trusts the `from` field; bind it to the authenticated session |
| 001 | Authentication treated as authorization | Owner check on every object read | Apply through a shared helper so new routes inherit it |

## 6. Retest results

Executed 2026-11-13 with `python scripts/run_security_suites.py`:

| Suite | Target build | Result |
| --- | --- | --- |
| Exploit proofs (`tests/security`) | Vulnerable | 6 / 6 reproduce |
| Regression (`tests/regression`) | Patched | 6 / 6 pass — attack blocked, feature intact |

## 7. Detection coverage

Executed 2026-11-13 with `python -m detections.validate`:

| Build | Attack requests alerted | Benign requests alerted |
| --- | ---: | ---: |
| Vulnerable | 13 / 13 | 0 / 22 |
| Patched | 13 / 13 | 0 / 22 |

One Sigma rule per finding is provided in [detections/rules](../detections/rules).
This is an in-sample check on a small labelled corpus; see
[detections/README.md](../detections/README.md) for its limits and each rule's
documented false positives and blind spots.

## 8. Limitations

- White-box, single service, single tester; no denial-of-service, infrastructure,
  dependency or social-engineering testing.
- Absence of a finding is not evidence of absence. The assessment covered the
  routes listed in scope at the commit under test.
- Severity reflects a hypothetical internet-facing deployment, as stated in §2.

## Appendix A — Reproduce the evidence

```bash
python -m pip install -r requirements-dev.txt
python scripts/run_security_suites.py
python -m detections.validate --output detection-report.json
python -m classification.render --check
```

Each command exits non-zero if any claim in this report stops being true. The
same commands run in [CI](../.github/workflows/ci.yml) on every change.
