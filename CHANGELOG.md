# Changelog

Notable changes, newest first. Dates are merge dates on `main`.

## Unreleased

- Detection engineering: six Sigma rules, opt-in audit telemetry in both
  fixtures, a labelled traffic replay scoring recall and false alerts on the
  vulnerable and patched builds, and pySigma conformance checks.
- Classification: CWE, OWASP Top 10:2025 / API Top 10 2023, MITRE ATT&CK and
  computed CVSS v3.1 scores for every finding, generated from one data file.
- Adversary emulation plan, sample assessment report, engagement kit (scoping
  questionnaire, rules of engagement, operating standard) and services page.
- Supply chain: GitHub Actions pinned to commit SHAs, exact dependency pins,
  CodeQL analysis, correctness linting, CODEOWNERS, issue and PR templates.

## 2026-11-12

- TRACEGUARD multi-step agent replay lab with hash-chained traces (#14).
- Scoped agent evals: 24 paired prompt-injection proposal cases and a scripted
  adversarial positive control (#11, #12).
- Offline AI-agent tool-authorization benchmark (#3).
- Dependabot configuration for Python and GitHub Actions (#4).
- CI starts each localhost fixture and runs exploit and regression suites (#2).
