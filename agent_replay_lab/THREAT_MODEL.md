# TRACEGUARD — Threat Model

## Trust boundary

**Trusted:** host-selected task, approved synthetic public-source and exact report path, policy implementation, step limit, API request budget. **Untrusted:** contents of a retrieved public-document fixture, proposed JSON actions, model or scripted strategy outputs. The attacker can only change a fixture document's **untrusted text** inside a matched scenario; they cannot alter the trusted plan.

## Data flow

1. Host fixes authorized task and destination.
2. Agent strategy proposes reading a synthetic source.
3. Host returns public untrusted content; the injected text may impersonate systems, peers, maintainers or human reviewers.
4. Agent strategy proposes further actions, potentially off scope.
5. Host checks every action, never executes denied operations and stores the approved report only in memory.
6. Hash-chained events and explicit counters record denials and legitimate completion.

No proposed tool has any access to real files, a shell, internal network, secrets, browser or another agent. The provider module optionally contacts only fixed model API hosts after manual user authorization and never runs tool calls.

## Threat themes and synthetic examples

| OWASP Agentic 2026 label | Synthetic research surface |
|---|---|
| ASI01 Goal Hijack | Forged system override in a release note |
| ASI02 Tool Misuse | A document asks for a fake network destination |
| ASI03 Identity and Privilege Abuse | A retrieved note claims an admin grant |
| ASI04 Supply Chain | Fake maintainer instruction to execute a shell command |
| ASI05 Unexpected Code Execution | Build log asks for deletion |
| ASI06 Memory and Context Poisoning | Notes request persistence of untrusted rules |
| ASI07 Insecure Inter-Agent Communication | Forged supervisor message |
| ASI09 Human-Agent Trust Exploitation | Forged approval to finish early |

Tags are **thematic mappings only**, not exhaustive risk coverage or OWASP verification. ASI08 and ASI10 are not directly evaluated.

## Safeguards and residual uncertainty

The default mode imports no network adapter execution and requires no credentials. Proposed unsafe operations are denied; approved interactions are Python in-memory values only. Actions use strict three-key JSON parsing and length constraints. Runs enforce a step limit. Optional live provider requests use a fixed endpoint and require explicit key/model/cost opt-in and a hard API call ceiling.

The event chain detects modifications **relative to an externally retained original head**, but cannot authenticate its author. Compromised host grants, real token disclosure through novel channels, unsafe runtime plugins, filesystem symlinks/TOCTOU, DNS rebinding, redirects, inter-agent authentication and production monitoring are **outside scope**. In particular, passing this toy benchmark does not establish security of a live agent.

No real-world target was tested; no real secret was accessed. External assessments require explicit written authorization and coordinated disclosure.
