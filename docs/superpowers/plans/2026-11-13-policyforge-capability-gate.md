# PolicyForge Capability Gate — Design and Implementation Plan (2026-11-13)

**Goal:** ship a deterministic, first-party, offline authorization benchmark for AI-agent tool calls.

**Architecture:** trusted `policy.json` defines actor/tool/action/resource grants and one-time approvals; untrusted synthetic plan steps are evaluated in order by a fail-closed Gate. Results are hash-chained and scored against `scenarios.jsonl`. No tool is invoked.

**Tech stack:** Python 3.11 stdlib, unittest, JSONL, GitHub Actions.

## Design choices

- Prefer pure offline simulation to deployment-ready proxy because the goal is reproducible defensive research, not access to real credentials.
- Authorizations are exact grants; no wildcard and no inheritance.
- Approvals come from trusted policy configuration, never tool output.
- Resource grammar is deliberately restrictive; external URLs and ambiguous encoded paths are rejected.
- Preserve existing CSA-LAB authorization boundaries.

## Tasks

- [x] Define regression tests for benign reads, unauthorized command execution, path traversal, approval forgery/replay, dependency escalation and audit integrity.
- [x] Implement `Gate` in `policyforge/engine.py` with transparent decisions.
- [x] Add 13 synthetic scenario fixtures and JSON benchmark.
- [ ] Run entire test suite and benchmark in CI; inspect results and remediate any failure.
- [ ] Review threat model and explicitly document non-production limitations.
- [ ] Publish signed, reproducible evidence once CI and independent review pass.

## Review focus

- Non-string or missing fields must fail closed.
- Encoded resources and prefix confusion must not widen scope.
- Approval cannot be reused, moved across resources or asserted in prompt text.
- Denied predecessor must not enable a successor.
- Log digests need external anchoring to detect total-log replacement.

**Verification commands**
```sh
python -m unittest discover -s policyforge/tests -p 'test_*.py' -v
python -m policyforge.benchmark --output policyforge-report.json
```
