# Extreme Cybersecurity Research Portfolio (2026–2027)

This roadmap builds on the already present `CSA-LAB` and `TRACEGUARD` work. Every project must be reproducible, authorized, benchmarked, and explicit about non-production limitations. No real-account testing, live scanning, malware deployment or credential collection is included.

## 1. POLICYFORGE — Trust-Boundary Verification Kernel (prototype delivered)

**Research question:** can a policy gate enforce external authorization for a multi-step AI agent when untrusted retrieved content proposes unauthorized tools, resource scopes and approvals?

**Implemented:** Python stdlib Gate, 13 synthetic cases, 12 unit tests, permission/approval replay defense, path normalization, dependency failure propagation, SHA-256 decision chain, JSON report and Actions CI.

**Extreme milestone:** replace simplistic in-memory approvals with trusted signed capability tokens, expiration, delegation chains and a mock MCP adapter. Add property-based fuzzing and mutation testing. Compare blocked unauthorized operations and false denial across 1,000+ seeded scenarios, reporting confidence intervals and a reproducible experiment manifest.

**Proof:** signed releases, JSONL scenario suite, human-readable threat model, test logs, provenance of generated results.

## 2. PROVENANCE-X — Software Supply Chain Attestation Verifier

**Research question:** can an auditor prove a build came from a reviewed commit and a trusted runner without trusting package names, README claims or mutable tags?

**Build:** independent CLI in Rust or Go that validates SLSA provenance subject digest, issuer/identity constraints, Sigstore verification, lockfile/SBOM consistency, and a bounded policy file. Include benign fixtures plus synthetic tampered packages, substituted commit IDs, rollback metadata, forged identities and unauthorized tag changes.

**Measures:** 0 unauthorized artifact accepts in threat fixtures; reproducible CI on Linux/macOS/Windows; 100% policy rule tests; benchmark verification latency and false rejection on valid builds.

**Non-goal:** do not label a third-party artifact malicious based on metadata alone.

## 3. ATLAS-RANGE — Agentic Red-Team/Blue-Team Replay Tournament

**Research question:** what security controls actually reduce multi-step tool misuse while preserving legitimate task completion?

**Build:** isolated simulated agents and mock services with no internet egress; paired benign/adversarial task families aligned to MITRE ATLAS and OWASP MCP. Attacker inputs are *synthetic* retrieved documents, tool descriptions and agent memories; defense tracks tool permission decisions, taint flow and audit evidence. No third-party targeting.

**Measures:** attack success rate, benign task completion, false-positive denial, decision latency, step-level traces and bootstrap confidence intervals. Publish seeds and anonymized replay artifacts.

**Non-goal:** producing weaponized real-world exploitation payload packs.

## 4. CLOUD-PATH — IAM and Kubernetes Privilege-Graph Auditor

**Research question:** can graph analysis expose privilege escalation routes hidden in long permission lists?

**Build:** offline Terraform/IAM/Kubernetes RBAC fixture parser; represent trust relationships and allowed actions as a directed typed graph; enumerate minimal attack paths to synthetic high-impact resources; compare alerts against a labeled ground truth set. Add remediation suggestions that remove just enough permissions to break the path.

**Measures:** precision, recall, mean time to identify risk, number of overprivileged identities and permission reductions after automated remediation.

**Non-goal:** production cloud scanning without explicit owner approval.

## Acceptance standards for all four projects

- Strong scope and authorization text with test-only targets
- Documented threat model and explicit boundaries of what was actually tested
- Tests written before remediation; baseline failures reproduced
- CI Linux verification; Python/Rust lint/type/format suites as appropriate
- No secrets, accounts, browser cookies, production credentials or user data in fixtures
- Reproducible evidence, separate raw data from claims, benchmark not tailored to a single example
- Clear negative controls; false-positive/false-negative accounting and failure modes

Suggested portfolio order: finish **POLICYFORGE** production-like mock adapter and evaluations, then **PROVENANCE-X**, then **ATLAS-RANGE**, then **CLOUD-PATH**. Each project should remain an independently reviewable package with a release and a research write-up.
