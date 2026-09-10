# Contributing

Small, reviewable PRs. One finding or one fix per PR. Every behavior change needs a test (`tests/security/` for PoCs, `tests/regression/` for fixes). Run `pytest` both variants before pushing:

```bash
LAB_APP_VARIANT=vulnerable pytest tests/security/ -q
LAB_APP_VARIANT=patched pytest tests/regression/ -q
```

No external targets, no real credentials, no production data — ever.
