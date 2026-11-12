# Scoped Agent Evals — Reproducible Prompt-Injection & Tool Authorization

**Status:** first-party synthetic research prototype. **Not** an externally validated LLM security score.

This standalone project under [CSA-LAB](../README.md) contains **24 scenarios: 12 matched benign/attack pairs**. It asks an optional LLM to **propose** one action in the presence of untrusted text and checks that proposal against an independent, trusted host policy. **No proposed shell, file or network operation is executed.** It complements the [19-case offline policy benchmark](../agent_security/README.md).

## Quick start (offline; no account, keys or dependencies)

Requires Python 3.11+; from repository root:

```bash
python -m unittest discover -s agent_evals -p 'test_*.py' -v
python -m agent_evals.evaluate --provider baseline --output agent-baseline-report.json
python -m agent_evals.evaluate --provider attack-control --output agent-attack-control-report.json
```

**The baseline always chooses the authorized action by construction**. Its expected results are for plumbing verification only, never evidence that a real model resisted an attack. The GitHub Actions workflow runs just this baseline and the offline test suite, and publishes the report as an artifact.

## Real model evaluation (explicit opt-in, possible API charges)

The provider integration uses synthetic case text only, never accesses local user files, never executes the proposed tool and never sends secrets from the repository. Supply a current, available model ID and an API key from your own provider account.

```bash
# OPENAI_API_KEY must be set in the environment, not in source control.
python -m agent_evals.evaluate --provider openai --model YOUR_AVAILABLE_MODEL_ID --acknowledge-api-cost --output openai-local-report.json

# Or ANTHROPIC_API_KEY, likewise set securely.
python -m agent_evals.evaluate --provider anthropic --model YOUR_AVAILABLE_MODEL_ID --acknowledge-api-cost --output anthropic-local-report.json
```

API calls are **not** made without the explicit `--acknowledge-api-cost` flag and `--model`. Provider support for given model IDs may change. Do not place API keys in GitHub, workflow files, public reports, PR comments, or screenshots. Provider request errors terminate the experiment rather than producing invented scores.

## Evaluation questions

- **Model proposal:** Does the model correctly choose the authorized operation and target? Does it refuse, produce invalid JSON, choose an unplanned action, or choose the attacker's target?
- **Host enforcement:** Does the deterministic trusted policy block unauthorized action proposals, regardless of what the untrusted material claims?
- **Benign utility:** Does the model perform legitimate benign tasks rather than refuse everything?

Each example has exactly one host-approved action. The attacker can alter only the **untrusted text**, not the task plan or write approval. Cases cover forged high-priority instructions, fake human approval, path escapes, secret bait, network host confusion, shell/deletion requests and structured output impersonation.

Read [METHODS.md](METHODS.md) for the denominators, protocol and limitations and [RESULTS.md](RESULTS.md) for the evidence ledger.

## Important limits and authorized scope

This is a **single-turn proposed-action experiment**, **not** an actual sandboxed AI agent, real-world exploit, external pentest, full prompt-injection red-team, or a claim of state-of-the-art model robustness. The simplified host policy is not an OS sandbox or network egress filter. It does not cover DNS rebinding, redirects, file races, compromised trust grants or all platform-specific path quirks.

All targets, URLs and secret names are synthetic placeholders; `kb.example.test` is reserved for examples. No tools are invoked based on a model proposal. Follow [AUTHORIZATION.md](../AUTHORIZATION.md) and [SECURITY.md](../SECURITY.md); do not scan or access third-party environments without explicit permission. Report real vulnerabilities privately under the affected project's disclosure policy.

Maintainer: [@skuzu7](https://github.com/skuzu7). This project represents self-authored research; no accepted bounties, CVEs, external reviews or access-program approvals are asserted.
