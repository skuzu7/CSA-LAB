# CSA LAB — Cyber Security Analysis Lab

Reproducible local lab for **vulnerability discovery → controlled validation → remediation → regression testing → documentation**.

All testing targets software we own, deliberately-vulnerable apps run locally, or educational labs/CTFs within their rules. No third-party systems. See [AUTHORIZATION.md](AUTHORIZATION.md).

## Quick start (Windows / Linux)

```bash
cd vulnerable-app
python -m venv .venv
# windows: .venv/Scripts/activate | linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py
# http://127.0.0.1:5000
```

Run tests:

```bash
pip install pytest
pytest tests/ -v
```

## Structure

- `vulnerable-app/` — intentionally vulnerable demo app (Flask, SQLite, local only). Binds 127.0.0.1 by default.
- `lab/` — Docker Compose for isolated local network (app + optional db).
- `tests/security/` — proof-of-concept checks that FAIL on vulnerable code, PASS after fix.
- `tests/regression/` — post-fix regression suite.
- `remediation/` — patches, one folder per finding.
- `writeups/` — one file per finding: context, threat model, cause, authorized reproduction, impact, evidence, remediation, patch, regression test, lessons.
- `docs/` — methodology, scope, responsible-use, threat-model.

## Findings

| ID | Title | Status | Write-up |
|----|-------|--------|----------|
| FINDING-001 | Broken object-level authorization (IDOR) in `/note/<id>` | vulnerable (fix in progress) | [writeups/finding-001.md](writeups/finding-001.md) |
| FINDING-002 | SQL injection in search parameter | vulnerable (fix in progress) | [writeups/finding-002.md](writeups/finding-002.md) |
| FINDING-003 | Path traversal in file download | vulnerable (fix in progress) | [writeups/finding-003.md](writeups/finding-003.md) |

## Who / why

Independent developer / defensive security researcher. This lab exists to practice AppSec the auditable way: every flaw has a controlled target I own, a failing test, a minimal patch, and a passing regression test. The emphasis is on the **fix**, not the exploit.

## Authorization summary

- Own code + local containers only. No external targets.
- CTF/Academy labs only under provider ToS.
- Bug bounty only inside program scope (none active at this time).
- Full statement: [AUTHORIZATION.md](AUTHORIZATION.md). Disclosure policy: [SECURITY.md](SECURITY.md).
