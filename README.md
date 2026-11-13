# CSA-LAB — Cyber Security Analysis Lab

[![Local Security Evidence](https://github.com/skuzu7/CSA-LAB/actions/workflows/ci.yml/badge.svg)](https://github.com/skuzu7/CSA-LAB/actions/workflows/ci.yml)
[![CodeQL](https://github.com/skuzu7/CSA-LAB/actions/workflows/codeql.yml/badge.svg)](https://github.com/skuzu7/CSA-LAB/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A reproducible application-security lab that takes six vulnerabilities through the
full professional cycle — **authorize → exploit → classify → detect → fix → retest →
report** — and adds offline research harnesses for AI-agent tool-use security.
Everything runs on localhost against synthetic data, and every number on this page
is asserted by a test in CI.

> **What this is not.** The vulnerabilities are planted educational fixtures. Nothing
> here is a third-party finding, CVE, bug-bounty award, client engagement, external
> certification or live-model evaluation, and no membership of any vendor
> trusted-access programme is claimed.

**Hiring for an assessment?** See [services](SERVICES.md), the
[sample report](reports/sample-assessment-report.md) and the
[engagement kit](engagement/README.md).

## The cycle, with evidence

| Stage | What exists | Verified by |
| --- | --- | --- |
| Authorize | [Authorization policy](AUTHORIZATION.md), [scope inventory](docs/scope.md), [threat model](docs/threat-model.md) | Reviewed before any target is added |
| Exploit | Six minimal proofs against the vulnerable build | `tests/security` — 6 / 6 reproduce |
| Classify | CWE, OWASP, MITRE ATT&CK and computed CVSS v3.1 per finding | [classification.md](docs/classification.md), generated and checked in CI |
| Detect | One Sigma rule per finding, replayed against real requests | 13 / 13 attack requests alerted, 0 / 22 benign, on both builds |
| Fix | Remediated build with the same API | `tests/regression` — 6 / 6 pass, feature intact |
| Emulate | Six-step ATT&CK-mapped intrusion chain | [adversary-emulation-plan.md](docs/adversary-emulation-plan.md) |
| Report | Client-format report with retest results | [sample-assessment-report.md](reports/sample-assessment-report.md) |

## Findings

| ID | Weakness | CWE | CVSS v3.1 | ATT&CK | Write-up | Detection |
| --- | --- | --- | ---: | --- | --- | --- |
| 001 | Broken object-level authorization (IDOR) | CWE-639 | 6.5 Medium | T1213 | [finding-001](writeups/finding-001.md) | [csa_001](detections/rules/csa_001_cross_owner_object_access.yml) |
| 002 | SQL injection | CWE-89 | 7.5 High | T1190 | [finding-002](writeups/finding-002.md) | [csa_002](detections/rules/csa_002_sql_injection_search.yml) |
| 003 | Path traversal | CWE-22 | 7.5 High | T1190, T1005 | [finding-003](writeups/finding-003.md) | [csa_003](detections/rules/csa_003_path_traversal_download.yml) |
| 004 | Forgeable session token | CWE-287 | 7.5 High | T1606.001 | [finding-004](writeups/finding-004.md) | [csa_004](detections/rules/csa_004_forged_session_token.yml) |
| 005 | Negative-amount transfer | CWE-839 | 7.5 High | T1565.001 | [finding-005](writeups/finding-005.md) | [csa_005](detections/rules/csa_005_negative_amount_transfer.yml) |
| 006 | Server-side request forgery | CWE-918 | 8.6 High | T1190, T1552.005 | [finding-006](writeups/finding-006.md) | [csa_006](detections/rules/csa_006_ssrf_internal_destination.yml) |

CVSS scores are computed from vectors by [`classification/cvss31.py`](classification/cvss31.py)
and rate each weakness as if the service were internet-facing. On loopback with
synthetic data the real risk is nil. Derivations and mapping rationale are in
[classification.md](docs/classification.md).

## Reproduce everything

Requires Python 3.11+ on Windows, macOS or Linux.

```bash
git clone https://github.com/skuzu7/CSA-LAB.git
cd CSA-LAB
python -m venv .venv
# Activate with .venv/Scripts/activate (Windows) or source .venv/bin/activate (macOS/Linux)
python -m pip install -r requirements-dev.txt

python scripts/run_security_suites.py                          # exploit proofs, then fix regressions
python -m detections.validate --output detection-report.json   # detection replay on both builds
python -m unittest discover -s detections/tests -t . -v        # rule logic and pySigma conformance
python -m unittest discover -s classification/tests -t . -v    # CVSS calculator and data integrity
```

`run_security_suites.py` checks that port 5000 is free, starts the **intentionally
vulnerable** Flask app on `127.0.0.1:5000`, runs the six proofs, stops it, starts
the **patched** app and runs the six regression tests. It fails closed if a fixture
does not start or a test fails. `tests/security` passes when the planted weaknesses
are reproduced; `tests/regression` passes when the patch prevents them and legitimate
behaviour survives. Do not run both suites against one build.

`detections.validate` replays 35 labelled requests and requires each attack to raise
exactly its own rule and each benign request to raise none. It is an in-sample
regression harness on a small corpus, not an estimate of production detection
efficacy — see [detections/README.md](detections/README.md).

## AI-agent tool-use security research

Three offline, deterministic harnesses study one question: when an agent reads
untrusted content, can the **host** stop it from acting outside its task? No real
model is called in CI and no proposed action is ever executed.

| Module | What it contains | Checks |
| --- | --- | --- |
| [TRACEGUARD](agent_replay_lab/README.md) | Multi-step replay of 16 matched cases (8 benign, 8 injected) across eight OWASP Agentic risk themes, with hash-chained decision traces | 26 unit tests; scripted baseline (48 steps, 0 denials) and attack control (56 steps, 8 off-scope requests, all denied) |
| [Scoped agent evals](agent_evals/README.md) | 24 synthetic cases (12 matched pairs) separating a model's *proposed* action from the host's authorization decision | 14 unit tests; scripted positive control: 12 / 12 attacker-goal proposals denied |
| [Tool-boundary benchmark](agent_security/README.md) | 19 policy-gate cases: task plans, write approval, path containment, restricted data, URL validation | 19 / 19 expected decisions |

```bash
python -m unittest discover -s agent_replay_lab/tests -v
python -m agent_replay_lab.runner --mode attack-control --output attack-control.json
python -m unittest discover -s agent_evals -p 'test_*.py' -v
python agent_security/offline_benchmark.py --json
```

These figures come from **scripted controls, not from GPT, Claude or any other
model**; eight denied requests are not eight vulnerabilities. Optional
OpenAI/Anthropic adapters exist for private experiments and require explicit
credentials, a model id and a cost acknowledgement. Read each module's results and
limitations ([TRACEGUARD results](agent_replay_lab/RESULTS.md),
[agent evals methods](agent_evals/METHODS.md)) before interpreting any number.

## Repository map

| Path | Contents |
| --- | --- |
| `vulnerable-app/`, `remediation/` | Intentionally insecure Flask + SQLite service and its patched equivalent, both bound to loopback |
| `tests/security/`, `tests/regression/` | Exploit proofs and fix regressions |
| `writeups/` | One evidence report per finding: context, root cause, reproduction, patch, residual risk |
| `classification/`, `docs/classification.md` | Taxonomy data, CVSS v3.1 calculator, generated classification page |
| `detections/` | Sigma rules, stateful enrichment, evaluator, labelled traffic, replay scorer |
| `docs/` | Scope, threat model, methodology, adversary emulation plan, responsible use |
| `reports/`, `engagement/`, `SERVICES.md` | Sample client report, engagement templates, service description |
| `agent_replay_lab/`, `agent_evals/`, `agent_security/` | AI-agent security research harnesses |
| `lab_telemetry.py` | Opt-in audit log (`LAB_AUDIT_LOG`) used by the detection replay |
| `lab/`, `Dockerfile` | Optional container tooling |

## Engineering controls

- GitHub Actions pinned to full commit SHAs, with `contents: read` as the default
  token permission and credentials not persisted after checkout.
- Exact dependency pins, updated by [Dependabot](.github/dependabot.yml).
- [CodeQL](.github/workflows/codeql.yml) on every pull request for the code meant
  to be correct; the intentionally vulnerable app is excluded and says why.
- Correctness linting, [code owners](.github/CODEOWNERS), a
  [security policy](SECURITY.md) and a pull-request checklist that blocks
  unverified claims.

## Authorized boundaries

- Testing is restricted to owned local fixtures or explicitly permitted educational environments.
- Never expose `vulnerable-app/` to a network or connect real data.
- Do not scan, exploit or access third-party systems without explicit written authorization.
- No active external bug-bounty programme is claimed.

The definitive rules are in [AUTHORIZATION.md](AUTHORIZATION.md), the
[scope inventory](docs/scope.md) and [SECURITY.md](SECURITY.md).

## Applied defensive engineering

The [freeband-nextjs](https://github.com/skuzu7/freeband-nextjs) project contains a
separate first-party authentication/session
[security review](https://github.com/skuzu7/freeband-nextjs/blob/main/SECURITY_REVIEW.md),
[STRIDE threat model](https://github.com/skuzu7/freeband-nextjs/blob/main/docs/THREAT_MODEL.md)
and CI workflow. It is an applied engineering case, not a claim of an externally
accepted vulnerability disclosure.

## License

[MIT](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) and the [changelog](CHANGELOG.md).
