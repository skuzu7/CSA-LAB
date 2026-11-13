# Contributing

Small, reviewable pull requests: one finding, one fix, one rule or one document
per change.

## Set up

```bash
python -m venv .venv && source .venv/bin/activate   # .venv\Scripts\activate on Windows
python -m pip install -r requirements-dev.txt
```

## Run everything CI runs

```bash
ruff check .
python scripts/run_security_suites.py
python -m unittest discover -s classification/tests -t . -v
python -m classification.render --check
python -m unittest discover -s detections/tests -t . -v
python -m detections.validate --output detection-report.json
python -m unittest discover -s agent_replay_lab/tests -v
python -m unittest discover -s agent_evals -p 'test_*.py' -v
python agent_security/offline_benchmark.py --json
```

## Rules

- **Scope first.** No external targets, no real credentials, no production data.
  A new target class needs `AUTHORIZATION.md` and `docs/scope.md` updated in an
  earlier commit.
- **Every behaviour change has a test.** A proof goes in `tests/security`, a fix
  in `tests/regression`, a detection in `detections/tests` plus a labelled
  request in `detections/traffic.jsonl`.
- **Every published number is asserted.** If a document states a count, score or
  rate, a test or CI step must fail when it stops being true. Regenerate
  `docs/classification.md` with `python -m classification.render`.
- **No inflated claims.** Lab results are described as lab results. No CVE,
  bounty, client, certification or model evaluation is implied unless it exists
  and is linked.
- **No offensive tooling.** Proofs are the minimum request that demonstrates a
  flaw on the local fixture.
