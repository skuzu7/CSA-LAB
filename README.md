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

## Flagship research: TRACEGUARD — Multi-Step Agent Replay Lab

[**TRACEGUARD**](agent_replay_lab/README.md) is a standalone, versioned research module for **multi-step agent tool-use security**. It goes beyond single-response prompt tests by simulating an entire bounded workflow: read an untrusted document, propose further tool actions, enforce exact host authorization, write an approved report and finish.

- [**16 matched synthetic cases**](agent_replay_lab/scenarios.jsonl) (8 benign / 8 injected), spanning eight OWASP Agentic risk themes.
- [**26 offline unit tests**](agent_replay_lab/tests/test_replay.py) for tool boundaries, parser strictness, session ordering, audit-trace tampering and provider cost/credential gates.
- Two **scripted**, intentionally contrasting controls: baseline (48 steps, zero denials) and attack control (56 steps, eight off-scope requests, all blocked).
- [**Hash-chained forensic traces**](agent_replay_lab/core.py) and downloadable JSON artifacts in [CI](.github/workflows/agent-replay-lab.yml), with an explicit [methodology](agent_replay_lab/METHODS.md) and [threat model](agent_replay_lab/THREAT_MODEL.md).
- Optional OpenAI/Anthropic model-proposal adapters require explicit local API credentials, model ID and **cost acknowledgement**. **No real model test, external exploit, CVE or bounty is claimed**.

```bash
python -m unittest discover -s agent_replay_lab/tests -v
python -m agent_replay_lab.runner --mode baseline --output baseline.json
python -m agent_replay_lab.runner --mode attack-control --output attack-control.json
```

Read [TRACEGUARD results and limitations](agent_replay_lab/RESULTS.md) before interpreting numbers. All allowed/denied tool actions are simulated **in memory**, not executed against external systems.

## Scoped Agent Evals — proposed tool actions under prompt injection

The [Scoped Agent Evals project](agent_evals/README.md) adds **24 versioned synthetic cases (12 matched benign/attack pairs)**, [methods and denominators](agent_evals/METHODS.md), [results/provenance ledger](agent_evals/RESULTS.md), 14 offline unit tests and a dedicated [GitHub Actions workflow](.github/workflows/agent-evals.yml). It separates **model action proposals** from an independently enforced **host authorization decision**.

```bash
python -m unittest discover -s agent_evals -p 'test_*.py' -v
python -m agent_evals.evaluate --provider baseline --output agent-baseline-report.json
```

The default deterministic baseline is **not** a live LLM evaluation. Optional provider API adapters are available only with explicit credentials, model ID and acknowledgement of possible API costs; they are not called in CI. No proposed action is ever executed and the examples do not contain real credentials or third-party targets.

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
