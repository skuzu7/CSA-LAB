# POLICYFORGE — Agent Capability Verification Research

**Goal:** prove that untrusted agent/model/tool-output text cannot invent tool permissions or human approval.

This is an **offline research harness**, not an MCP server and not a production sandbox. It executes **zero tools**, uses **zero external network requests**, and tests synthetic repository URLs only.

## Run

Requires Python 3.11+; no third-party dependencies.

```sh
python -m unittest discover -s policyforge/tests -p 'test_*.py' -v
python -m policyforge.benchmark --output policyforge-report.json
```

`policy.json` is trusted configuration. `scenarios.jsonl` contains synthetic plans and expected decisions. The benchmark emits one JSON report with false-allow and false-deny counts; a regression exits nonzero.

## Security architecture

1. **Explicit capability grants:** exact actor, tool, action and canonical `repo://owner/repo/path` scope. Prefix boundaries prevent `docs/` from matching `docs2/`.
2. **Untrusted inputs stay untrusted:** tool-output and retrieved text use the same policy gate; `source` metadata never becomes an authorization grant.
3. **Human approval outside the model:** destructive `delete`, `execute`, `publish`, `secrets.read` and `git.force_push` require an exact approval object already held in trusted policy, matched to actor/tool/action/resource, consumed once per Gate instance.
4. **Multi-step containment:** a denied predecessor cannot authorize a dependent step; duplicate IDs and unsafe path/URL encodings are rejected.
5. **Audit integrity:** each decision is hashed with its predecessor to produce a deterministic SHA-256 hash chain. A digest is **not** equivalent to trusted immutability unless its head is anchored externally.

## Threat model and limits

Threats studied: tool-output prompt injection, privilege escalation by scope confusion, forged approvals, approval replay, dependency-based escalation, path traversal, external URL substitution, and actor spoofing.

Limitations: this code does **not** run or sandbox a tool, authenticate human identities, verify cryptographic approvals, secure the local policy file, resolve symlinks on a filesystem, or prove production security. The approval registry is a synthetic trusted fixture. High-risk production use would require an independently authenticated approval service, secure isolation, scoped credentials, audit anchoring, schema/version enforcement, and integration tests on real authorized adapters.

## Research alignment

- OWASP MCP Top 10: token/secret exposure, scope creep, tool poisoning, command injection, authorization, telemetry.
- OWASP Agentic Skills Top 10: skill execution as an elevated trust boundary.
- MITRE ATLAS: agent tool invocation and context/tool poisoning.

All scenarios are synthetic and within [AUTHORIZATION.md](../AUTHORIZATION.md). No third-party testing or exploitation is included.

## Next milestones for a publication-quality project

- Integrate a *mock* MCP adapter; validate the tool schema before authorization.
- Support capability expiration and delegation constraints (no privilege amplification).
- Compare baseline vs policy-enforced suites with bootstrap confidence intervals and false-deny cost.
- Add policy mutation testing, property-based fuzzing, external audit-head anchoring and reproducible signed release artifacts.
