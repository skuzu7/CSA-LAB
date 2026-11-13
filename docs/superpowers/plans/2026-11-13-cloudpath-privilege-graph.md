# CLOUD-PATH privilege graph implementation plan — 2026-11-13

> For agentic workers: execute tasks using superpowers:executing-plans, verifying each result with tests.

**Goal:** deliver a reproducible offline identity permission graph analysis with high-risk resource reachability and minimal grant removal recommendations.

**Architecture:** Python stdlib parses explicitly resolved synthetic grant edges, uses bounded DFS to enumerate independent routes and an edge-split residual flow network to calculate minimum removable permission cuts. A fixture supplies expected reachability labels; benchmark outputs JSON.

**Stack:** Python 3.11 unittest and GitHub Actions.

**Scope:** no real cloud environment, no SDK or credentials, no attacks outside synthetic fixtures.

## Tasks
- [x] Add 10 unit tests covering condition failures, deny precedence, unrevocable paths, min cut, invalid graphs and deterministic paths.
- [x] Implement `cloudpath/engine.py` with strict graph validation, bound checks, paths and cut.
- [x] Add labeled synthetic fixture and JSON benchmark.
- [ ] Run complete tests and benchmark in CI; fix any failures.
- [ ] Include source-to-permission provenance in graph in a follow-up.
- [ ] Add an actual offline Kubernetes/IAM semantics parser with independently reviewed policy reference tests.

## Review focus
- Cycles do not create infinite enumeration.
- Multiple independent paths require multiple cuts.
- Explicit denies override matching allows.
- False policy positives are clearly disclosed.
- No real infrastructure is accessed.

## Commands
```sh
python -m unittest discover -s cloudpath/tests -p 'test_*.py' -v
python -m cloudpath.benchmark --output cloudpath-report.json
```
