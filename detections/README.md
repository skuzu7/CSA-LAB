# Detection engineering

One [Sigma](https://sigmahq.io/) rule per planted finding, each validated against
real requests to the lab fixtures. The loop this directory closes is
**attack → telemetry → detection → fix → the attempt still alerts**.

| Finding | Rule | Log source | What it keys on |
| --- | --- | --- | --- |
| 001 IDOR | [`csa_001`](rules/csa_001_cross_owner_object_access.yml) | application audit | actor differs from the object's stored owner |
| 002 SQL injection | [`csa_002`](rules/csa_002_sql_injection_search.yml) | web server | quote followed by a SQL operator, UNION, `;` or `--` |
| 003 Path traversal | [`csa_003`](rules/csa_003_path_traversal_download.yml) | web server | parent-directory sequence, raw or encoded |
| 004 Forged token | [`csa_004`](rules/csa_004_forged_session_token.yml) | application audit + enrichment | token fails verification, or its subject was never issued one |
| 005 Negative transfer | [`csa_005`](rules/csa_005_negative_amount_transfer.yml) | application audit | amount below zero |
| 006 SSRF | [`csa_006`](rules/csa_006_ssrf_internal_destination.yml) | web server | fetch target is loopback, link-local, RFC 1918 or a local scheme |

## Measured result

```bash
python -m pip install -r requirements-dev.txt
python -m detections.validate --output detection-report.json
python -m unittest discover -s detections/tests -t . -v
```

`validate` starts each fixture on `127.0.0.1:5000` with the opt-in audit log
(`LAB_AUDIT_LOG`, see [`lab_telemetry.py`](../lab_telemetry.py)), replays the 35
labelled requests in [`traffic.jsonl`](traffic.jsonl), and requires every attack
to raise exactly its own rule and every benign request to raise none.

| Fixture | Attack requests alerted | Benign requests alerted | Attack outcome |
| --- | ---: | ---: | --- |
| Vulnerable | 13 / 13 | 0 / 22 | 11 succeed (HTTP 200), 2 traversal variants miss the file (404) |
| Patched | 13 / 13 | 0 / 22 | all 13 blocked or neutralized; the attempt still alerts |

The 22 benign requests include 8 hard negatives chosen to look like attacks
(`o'brien`, `rock or roll`, `union select committee`, `notes..final.txt`, a
transfer rejected for insufficient funds, and similar).

**What these numbers are and are not.** The rules and the corpus were written by
the same author against a six-endpoint fixture, so this is an in-sample regression
harness: it proves the rules fire on the documented payloads and stay quiet on the
listed look-alikes, and it will catch a change that breaks either. It is not an
estimate of detection efficacy on unseen payloads or production traffic. Known
false positives and blind spots are written into each rule's `falsepositives`
field and pinned by tests in
[`tests/test_rules_offline.py`](tests/test_rules_offline.py) — for example
alternate IP notations (`http://2130706433/`) evade rule 006 by design, because
that is a prevention problem (resolve, then allowlist), not a signature problem.

One side effect worth noticing in the report: the two benign apostrophe searches
return HTTP 500 from the vulnerable fixture and 200 from the patched one. The
injection flaw breaks ordinary users before any attacker shows up.

## How the pieces fit

- [`rules/`](rules) — standard Sigma YAML. Web-server rules use the W3C field names
  (`cs-uri-stem`, `cs-uri-query`); application rules use the audit fields the
  fixtures emit (`actor`, `resource_owner`, `token_subject`, `token_valid`, `amount`).
- [`enrich.py`](enrich.py) — the one stateful step. Sigma evaluates single events,
  so "this token's subject was never issued a token" is computed as a lookup and
  added as `token_issued` before rule 004 runs. Reproduce it as a lookup table in
  the target SIEM.
- [`engine.py`](engine.py) — a small evaluator (about 220 lines) for the subset of Sigma these
  rules use, so CI can score them without a SIEM. It raises on any unsupported
  construct rather than half-matching.
- [`tests/test_sigma_conformance.py`](tests/test_sigma_conformance.py) — loads every
  rule with the reference [pySigma](https://github.com/SigmaHQ/pySigma) library and
  runs its offline validators, which also enforces RE2-compatible regular
  expressions. ATT&CK tag validators are not run because they fetch data at run time.

## Safety boundary

The replay contacts loopback only. Payloads that would reach a real
cloud-metadata address or a private network (`169.254.169.254`, `10.0.0.0/8`,
`file://`) are exercised offline against synthetic events and are never sent.
