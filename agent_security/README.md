# Offline Agent Tool-Boundary Benchmark

**Research type:** deterministic defensive control tests. **Not** an LLM benchmark, a jailbreak benchmark, a claim of resistance to prompt injection in a real model, or a third-party vulnerability report.

## Purpose and threat model

AI agents can receive untrusted retrieved text, web content, code comments, repository files, logs and tool results. Such content may *instruct* an agent to perform actions it is not authorized to perform. A model-only prompt is not an authorization boundary.

This fixture exercises a **host-enforced tool authorization layer**. It deliberately distinguishes:

- An **untrusted tool request or content string**, which cannot expand permissions.
- A **trusted task plan**, created out of band by the host/operator, with exact operation + target grants.
- A **separate human-approved write registry**, also supplied by the host rather than from model-generated text.
- File workspace containment checks, sensitive-name restrictions and a simple HTTPS host allowlist.

The harness does not execute any proposed tool calls. It makes **authorization decisions only**, using temporary synthetic files on the researcher's own machine. No DNS lookups, outbound HTTP, model APIs, token handling or exploitation are performed.

## Run

Requires Python 3.11+; no extra packages:

\`\`\`bash
python agent_security/offline_benchmark.py
python agent_security/offline_benchmark.py --json
\`\`\`

Successful execution exits 0 and prints the synthetic case outcomes. Any mismatch between expected and actual allow/deny decisions exits 1. The CI checks this exit status in addition to the original six security demonstrations and six patch regressions.

## Case coverage

There are **19 explicitly enumerated cases** in \`cases()\`:

| Class | Example | Expected result |
| --- | --- | --- |
| Valid authorization | Read approved workspace documentation | Allow |
| Valid approved write | Write exact report target with separately provided human approval | Allow |
| Valid network request | A syntactically allowed HTTPS URL in the trusted task plan | Allow decision only (no network request) |
| Tool-result instruction | Untrusted text says to expand scope | Deny extra unplanned action |
| Sensitive information | Read \`.env.production\` or \`.ssh/id_rsa\` | Deny |
| File escape | Parent traversal, absolute path or symlink outside workspace | Deny |
| Dangerous tool | Execute shell or delete files | Deny unsupported operations |
| Unapproved write | Write without approval, or to a different path | Deny |
| URL confusion | Metadata-IP URL, lookalike host, userinfo trick | Deny |
| Scope expansion | Unapproved HTTPS path or HTTP POST | Deny |

The runner reports **evaluated, passed, failed, skipped, false_allows and false_denies**. A symlink case is explicitly reported as *skipped* when the operating system does not allow creating the test link. Never silently count skipped cases as passes.

## Interpreting results correctly

Passing 19/19 checks means that **these 19 synthetic tool-policy decisions** matched the specified expectations. It does **not** mean 100% resistance to adversarial prompts, complete prompt-injection defense, secure browser execution, or broad real-world coverage.

There is **no language model under test**; no attack success rate or empirical model-comparison metric is measured. Even in a real agent, a tool policy can only enforce the grants it receives from a **trusted host**. If the model itself can modify the trusted plan, approvals or execution boundary, this benchmark does not provide security.

This simplified example intentionally lacks:

- Actual process isolation, a sandbox, or operating-system permissions.
- DNS resolution pinning, network egress proxy, redirect validation and TLS verification.
- Atomic protection against file-system time-of-check/time-of-use (TOCTOU) races.
- Strong case-insensitive path semantics across platforms, Unicode normalization, or Windows-specific path edge cases.
- Real model tool-use traces, dataset sampling, attacks by external researchers or statistical confidence intervals.
- User identity verification, durable user consent and an authentication-backed approval mechanism.

**Production defensive systems require** host-side enforcement, process and network isolation, auditable approval receipts, robust canonicalization, secret management and independent security review. This code is an educational test fixture.

## Research ethics and reproducibility

This module uses only the repository's own code and OS temporary directories. All names, targets, URLs and secrets are synthetic. \`kb.example.test\` is a reserved illustrative domain; the benchmark never contacts it. No third-party scanning, credential access, exfiltration or live exploitation occurs.

Researcher: Antonio Caetano (@skuzu7). See [AUTHORIZATION.md](../AUTHORIZATION.md) and [SECURITY.md](../SECURITY.md). The [six original planted web-app findings](../README.md) are a separate AppSec exercise; these 19 policy checks must not be conflated with 19 vulnerabilities or bug-bounty findings.

## Next methodological improvements

For a meaningful *AI-agent* security evaluation, add a versioned set of consented agent traces, a defined attacker/defender threat model, independent human annotations, an actual LLM harness, benign/attack pairs, metrics stratified by weakness class, repeated trials and error analysis. Report the model/version, prompts, sampling configuration, tool harness and dataset limitations. Do not claim SOTA or a model success rate without such measurements.
