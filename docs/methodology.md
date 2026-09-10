# Methodology

Loop per finding: **discover → validate (controlled) → remediate → regression-test → document**.

1. Discover: code review + manual test against localhost fixture. No scanners against anything we don't own.
2. Validate: minimum PoC in `tests/security/`, asserting the flaw exists. One request, no payload chaining beyond proof.
3. Remediate: smallest correct patch in `remediation/`, fail-closed, with comment referencing the finding ID.
4. Regression-test: `tests/regression/` asserts flaw gone AND legitimate function intact (fix must not break the feature).
5. Document: `writeups/finding-*.md` with the 10-section template (context → lessons). Fix gets more words than exploit.

Severity is lab-relative (High/Medium/Low against demo assets), never inflated to real-world CVE language.
