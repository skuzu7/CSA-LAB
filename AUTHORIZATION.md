# AUTHORIZATION.md

This document defines the authorized scope for this laboratory. It is the single source of truth for target authorization. Anything not explicitly listed here is **NOT authorized**.

## 1. Authorized targets and research surfaces

1. **First-party code in this repository**, including the intentionally vulnerable vulnerable-app/, local lab/ fixtures, and the offline research modules agent_security/, agent_evals/, agent_replay_lab/, classification/, and detections/. These are run on the researcher's own machine or in repository-controlled CI with synthetic data.
2. **Deliberately vulnerable applications run locally**, such as this repository's demo app or an OWASP Juice Shop instance started by the researcher in local Docker. The service must remain on loopback or an isolated local container network; it must not be exposed to public networks.
3. **Optional model-provider evaluation** through the explicitly opt-in adapters in agent_evals/ or agent_replay_lab/. This is limited to synthetic benchmark text sent to the adapter's fixed official provider API endpoint, using a key supplied by the researcher through a local environment variable and an explicit acknowledgement of possible API cost. No model-proposed tool action is executed. This is not authorization to test the provider, other customers, or any external system.
4. **Educational labs and CTFs** (for example PortSwigger Web Security Academy, Hack The Box, or TryHackMe) only when the researcher has selected a specific lab and the activity is permitted by the provider's current terms and published scope. No external educational target is currently recorded as active in docs/scope.md.
5. **Bug bounty programs** only after the program name, exact target, scope URL, permitted methods, and testing window are recorded in this file and docs/scope.md before work begins. No external bug bounty program is currently active.

## 2. Explicitly prohibited

- Testing, scanning, probing, or accessing any system the researcher does not own and does not have explicit written authorization to test.
- Social engineering, phishing, credential stuffing, or attacks on real users or real user data.
- Collection, decryption, export, or use of third-party credentials, browser cookies, session tokens, or authentication material.
- Exfiltration, persistence, lateral movement, denial of service, or activity outside the explicitly authorized local fixture.
- Executing model-proposed shell, file, browser, or network actions against real systems as part of the offline agent benchmarks.
- Using findings from this lab against any third party.
- Representing planted lab findings or synthetic benchmark outcomes as real-world breaches, CVEs, accepted bug-bounty reports, paid engagements, or model robustness results.

## 3. Environment controls

- The demo app binds to 127.0.0.1; local container networking is isolated and is not published to the public internet.
- Test data is synthetic (including fictional alice and bob users). No production customer data or real credentials are used.
- Default test and CI paths are offline and require no provider credentials.
- Optional model-provider evaluations are user-initiated, use synthetic case text only, and require a local environment key plus explicit cost acknowledgement. Keys must never be committed, printed in reports, or placed in workflow files.
- CI runs the local fixtures and offline harnesses; it does not scan external targets or execute proposed agent tools.

## 4. How authorization is evidenced

- This file and docs/scope.md define the authorized target inventory and non-goals.
- Git history records who changed the scope and when.
- Each vulnerability write-up's "Authorized reproduction" section names the exact local target instance and relevant commit.
- CI configuration and test code show that the security suites execute against repository-controlled local fixtures.
- Optional provider API evaluations are not target assessments; their model, dataset, run configuration, and cost acknowledgement must be recorded with the generated research report.

## 5. Use of results

Results are used for remediation patches in this repository, regression tests, defensive documentation, detection-rule validation, and synthetic research evaluation. Proof-of-concept code is limited to the minimum necessary to demonstrate a planted local flaw and verify its fix. No autonomous remote scanner, credential-harvesting workflow, persistence tooling, or production exploitation workflow is authorized by this document.

## 6. Change control

Any new target class, external program, live system, or testing method requires an update to this file and docs/scope.md **before** testing begins. Undocumented targets and methods are out of scope by default. Provider terms, program rules, and written owner authorization override this document wherever they are stricter.

*Last reviewed: 2026-11-14. Owner: repository maintainer (individual researcher).*
