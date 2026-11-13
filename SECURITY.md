# Security Policy

## Supported scope

This repository is a **research and educational laboratory**, not production software. The app in `vulnerable-app/` is intentionally insecure: do not deploy it, connect it to real data, or expose it to a network.

| Component | Status |
| --- | --- |
| `vulnerable-app/` | Intentionally vulnerable local fixture |
| `remediation/` | Patched examples documented per finding |
| `tests/security/` | Controlled reproduction tests |
| `tests/regression/` | Tests for patched behavior |
| `lab/` | Isolated local environment |
| `detections/` | Sigma rules and a loopback-only traffic replay |
| `classification/` | Taxonomy data and CVSS v3.1 calculator |
| `agent_replay_lab/`, `agent_evals/`, `agent_security/` | Offline, synthetic AI-agent research harnesses |

The **six planted findings (001–006)** are documented under [`writeups/`](writeups/) and already have accompanying mitigation and regression material. These are educational exercises, not undisclosed vulnerabilities in third-party services.

## Reporting an unexpected vulnerability

Please **do not post secrets, personal information, or live exploit details in a public issue**. If GitHub private vulnerability reporting is enabled, use it. Otherwise contact the maintainer through the [LinkedIn profile](https://br.linkedin.com/in/antonioccjr) linked from [@skuzu7](https://github.com/skuzu7) to arrange private disclosure.

Include the affected file or commit, a minimal reproduction against your own local clone, impact, and a suggested fix. The maintainer aims to triage reports within seven days; this is a best-effort goal, not a service guarantee.

## Authorized targets and disclosure

- In scope: this repository's code and authorized, local instances only.
- Out of scope: external deployments, third-party services, real user data, social engineering, and denial-of-service tests.
- The [authorization policy](AUTHORIZATION.md) and [scope inventory](docs/scope.md) are authoritative and must be updated before any new target is included.
- Coordinated disclosure is preferred for unexpected genuine issues; planted demonstration flaws are public by design.
- No bounty is offered and no active external bug-bounty program is claimed.

All fixtures are synthetic. The laboratory is designed to operate without handling personal data.
