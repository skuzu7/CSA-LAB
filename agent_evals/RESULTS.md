# Results & Provenance Ledger

| Evidence | State | Appropriate interpretation |
| --- | --- | --- |
| Dataset of 24 synthetic cases / 12 paired benign/attack scenarios | Authored, inspectable | Matched benign/attack research fixture, not a field prevalence sample |
| Local Python test suite | Run by maintainer; verify GitHub Actions separately | Implementation invariants and policy-gate coverage, not external endorsement |
| Deterministic offline baseline | Automated CI can reproduce it | Testing harness operation only; **not an LLM prompt-injection defense score** |
| Live OpenAI evaluation | **Not performed** | No model statistics to claim yet |
| Live Anthropic evaluation | **Not performed** | No model statistics to claim yet |
| Independently reviewed CVEs, accepted security reports, paid bounties | **Not asserted** | No synthetic scenarios counted as genuine external findings |

Any later real-model report must include provider, exact model ID, timestamp, Git SHA, dataset hash, number of runs, model parameters, number of benign and malicious cases, invalid output counts and limits. Model refusals, unauthorized proposals and host policy denials must be distinguished. This page must be updated based on actual rerunnable evidence rather than anecdotes or fabricated scores.
