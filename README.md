# CSA LAB — Cyber Security Analysis Lab

A **localhost-only application-security lab** showing a complete, inspectable defensive workflow:
scope and authorization → reproducible weakness → root cause → minimal patch → regression test.

**Important:** The vulnerabilities are planted educational fixtures. They are **not** third-party findings, CVEs, bug-bounty awards, or evidence of a professional penetration-testing engagement.

## Reproduce all six cases (Windows, macOS or Linux)

Requires Python 3.11+.

```bash
git clone https://github.com/skuzu7/CSA-LAB.git
cd CSA-LAB
python -m venv .venv
# Activate with .venv/Scripts/activate (Windows) or source .venv/bin/activate (macOS/Linux)
python -m pip install -r vulnerable-app/requirements.txt
python scripts/run_security_suites.py
```

The runner checks that port 5000 is free, starts the **intentionally vulnerable** Flask app on `127.0.0.1:5000`, runs the six controlled demonstrations, stops it, starts the **patched** app on the same loopback address, and runs the six regression tests. It fails closed if the fixture does not start or a test fails. See [CI](.github/workflows/ci.yml).

The `tests/security/` suite **passes when the planted weaknesses are reproduced**; the `tests/regression/` suite **passes when the patched app prevents those weaknesses and retains legitimate behavior**. Do not run both suites against one server variant.

These are code-level assertions, not a claim of formal third-party review. To verify results yourself, run the commands above or inspect the [GitHub Actions history](../../actions).

## Findings and evidence

| Finding | Weakness demonstrated in the local fixture | Evidence |
| --- | --- | --- |
| 001 | Broken object-level authorization / IDOR | [Write-up](writeups/finding-001.md) |
| 002 | SQL injection | [Write-up](writeups/finding-002.md) |
| 003 | Path traversal | [Write-up](writeups/finding-003.md) |
| 004 | Forgeable session token | [Write-up](writeups/finding-004.md) |
| 005 | Negative-amount transfer logic | [Write-up](writeups/finding-005.md) |
| 006 | Server-side request forgery (SSRF) | [Write-up](writeups/finding-006.md) |

Each write-up explains the threat boundary, cause, local reproduction, patch, residual limitations and regression behavior. The exact assertions are in [planted-finding tests](tests/security/test_findings_vulnerable.py) and [patch regression tests](tests/regression/test_fixes.py).

## Repository structure

- `vulnerable-app/`: intentionally insecure Flask+SQLite service, bound to loopback
- `remediation/patched_app.py`: remediated equivalent fixture
- `scripts/run_security_suites.py`: local/CI test orchestration and process teardown
- `tests/security/`: six positive demonstrations of planted weaknesses
- `tests/regression/`: six checks of defensive behavior after the patch
- `writeups/`: individual evidence reports
- `lab/`: optional Docker tooling
- `docs/`: boundaries, threat model, research methodology

## Agent tool-boundary security (offline benchmark)

A separate [AI-agent tool authorization benchmark](agent_security/README.md) contains **19 synthetic, deterministic policy-gate cases** for trusted task plans, explicit write approval, path containment, restricted data, URL validation, and untrusted tool-result instructions.

```bash
python agent_security/offline_benchmark.py --json
```

CI publishes a machine-readable case report as a workflow artifact. **This is not an LLM/prompt-injection robustness evaluation**: no real model is called, no commands are executed, and no external network requests occur. The tests evaluate a small host-enforced policy boundary only.

## Authorized boundaries

- Testing is restricted to owned local fixtures or explicitly permitted educational environments.
- Never expose `vulnerable-app/` to the internet or connect real data.
- No active external bug bounty is claimed.
- Do not scan, exploit, or access third-party systems without explicit authorization.

The definitive rules are in [AUTHORIZATION.md](AUTHORIZATION.md), the [scope inventory](docs/scope.md) and [SECURITY.md](SECURITY.md).

## Applied defensive engineering

The [freeband-nextjs](https://github.com/skuzu7/freeband-nextjs) project contains a separate first-party authentication/session [security review](https://github.com/skuzu7/freeband-nextjs/blob/main/SECURITY_REVIEW.md), [STRIDE threat model](https://github.com/skuzu7/freeband-nextjs/blob/main/docs/THREAT_MODEL.md) and CI workflow. It is an applied engineering case, not a claim of an externally accepted vulnerability disclosure.
