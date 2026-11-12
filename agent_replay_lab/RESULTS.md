# TRACEGUARD v0.1 — Results Ledger

**Executed locally:** 26 Python `unittest` checks, baseline scripted replay, adversarial scripted replay and report validation. A GitHub Actions run independently checks the same source after PR submission. **No live OpenAI/Anthropic model evaluation has been run as part of this release.**

| Evaluation | Cases | Benign completed | Attack-case legitimate tasks completed | Denied attacker-goal proposals | Denied tool actions | Steps |
|---|---:|---:|---:|---:|---:|---:|
| Scripted negative control | 16 | 8/8 | 8/8 | 0 | 0 | 48 |
| Scripted positive control | 16 | 8/8 | 8/8 | 8 | 8 | 56 |
| OpenAI live model | **Not run** | — | — | — | — | — |
| Anthropic live model | **Not run** | — | — | — | — | — |

The eight denials are intentionally scripted **synthetic checks, not eight identified vulnerabilities or demonstrations of model resilience**. The tool requests were never executed against a real system. An attacker-goal request is only counted when it violates the trusted plan; a valid finish is not considered an attack.

Reproduce from repository root:

```bash
python -m unittest discover -s agent_replay_lab/tests -v
python -m agent_replay_lab.runner --mode baseline --output baseline.json
python -m agent_replay_lab.runner --mode attack-control --output attack-control.json
```

The [CI workflow](../.github/workflows/agent-replay-lab.yml) verifies exact counters and every hash-chain link, and uploads two provenance-labelled JSON artifacts. [Methods](METHODS.md) defines the denominators and limitations.

## Evidence required for later external claims

A model-specific result requires valid paid-provider consent, exact model ID, dataset SHA, date, response configuration, repeated independent trials, raw/invalid/refusal counts, task utility, proposed-attack rates and independent review. An accepted vulnerability requires an unrelated maintainer or program to confirm it. No CVP/Daybreak admission or third-party security acceptance is asserted by this research.
