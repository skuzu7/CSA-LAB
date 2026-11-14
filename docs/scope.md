# Scope — target and research-surface inventory

Anything not listed here is out of scope. This table distinguishes local research code from actual systems that may be tested.

| Target or research surface | Location / execution | Owner | Authorization basis | Current status |
|---|---|---|---|---|
| vulnerable-app (intentionally vulnerable Flask demo) | 127.0.0.1:5000, local checkout | Researcher (first-party code) | [AUTHORIZATION.md §1.1](../AUTHORIZATION.md) | Active local fixture; synthetic data only |
| lab/ Compose environment | Local isolated container network | Researcher | [AUTHORIZATION.md §1.1](../AUTHORIZATION.md) | Active local fixture; not exposed publicly |
| agent_security/ offline tool-boundary benchmark | Local Python process and temporary synthetic files | Researcher | [AUTHORIZATION.md §1.1](../AUTHORIZATION.md) | Active; policy decisions only, no tools executed |
| agent_evals/ synthetic action-proposal evaluation | Local Python process; synthetic scenario text | Researcher | [AUTHORIZATION.md §1.1](../AUTHORIZATION.md) | Active offline baseline; live provider runs are optional and separately recorded |
| agent_replay_lab/ TRACEGUARD multi-step replay | Local Python process; synthetic documents and in-memory actions | Researcher | [AUTHORIZATION.md §1.1](../AUTHORIZATION.md) | Active; scripted strategy and offline tests, no real tools executed |
| classification/ and detections/ | Local Python tests and labelled synthetic traffic replay | Researcher | [AUTHORIZATION.md §1.1](../AUTHORIZATION.md) | Active; no production telemetry or external targets |
| Optional model-provider APIs | Fixed official provider API endpoints, only after explicit local opt-in; synthetic case text only | Provider operates endpoint; researcher owns API account | [AUTHORIZATION.md §1.3](../AUTHORIZATION.md) and provider terms | Not part of default CI; each run must record model/version, dataset, settings, trial count, and cost acknowledgement |
| PortSwigger Academy / other educational labs | Provider-hosted lab target, only within selected lab scope | Respective provider | Current provider terms and lab rules; record selected lab before testing | No external lab currently recorded as active |
| External bug bounty | No target currently authorized | Respective program owner | Written program scope and permitted-method rules must be added before testing | **NONE ACTIVE** |

## Non-goals

- No third-party production systems, public IP ranges, customer accounts, real user data, or real credentials are in scope.
- No external security scanning, credential testing, social engineering, persistence, lateral movement, or denial-of-service activity is authorized.
- Offline agent benchmarks make authorization decisions only; they do not execute model-proposed shell, file, browser, or network operations.
- Optional model-provider calls evaluate synthetic text and are not security tests of the provider or its infrastructure.

See [AUTHORIZATION.md](../AUTHORIZATION.md) for the full rules. Any target or method not recorded above is out of scope.
