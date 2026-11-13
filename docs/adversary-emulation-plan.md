# Adversary emulation plan — web application intrusion chain

A threat-informed, open-book (purple-team) exercise against this repository's own
fixture. Each step names the adversary behaviour, the exact procedure, the telemetry
it produces, the detection that must fire and the control that must stop it. Every
cell in the results table is backed by a test that runs in CI.

## 1. Authorization and scope

| Item | Value |
| --- | --- |
| Target | `vulnerable-app/` and `remediation/patched_app.py`, bound to `127.0.0.1:5000` |
| Owner / authorizer | Repository maintainer, per [AUTHORIZATION.md](../AUTHORIZATION.md) §1.1 |
| Data | Synthetic only (`alice`, `bob`, fixture ledger and files) |
| Out of scope | Any other host, any third-party service, any real cloud-metadata endpoint |
| Stop condition | Any request leaving loopback, or any unexpected process on port 5000 |

## 2. Threat scenario

An external operator with no credentials targets an internet-facing web
application to read other users' data, obtain service credentials and alter
financial records. This is a generic intrusion pattern assembled from the six
weakness classes present in the fixture. **No named threat group is emulated**;
group-specific emulation requires cyber threat intelligence about that group's
procedures, which this lab does not have and does not claim.

## 3. Attack path

```text
[1] SQL injection ──> schema and record discovery
[2] Path traversal ─> application source disclosed ─> token scheme understood
[3] Token forgery ──> session as any user
[4] IDOR ───────────> every user's notes
[5] SSRF ───────────> internal-only configuration (metadata-style secret)
[6] Negative transfer ─> ledger manipulation (objective reached)
```

Step 2 is what makes step 3 cheap: once the source is readable, the operator sees
that a session token is only an encoded user name. Steps 1, 4, 5 and 6 are
independent of each other and are ordered here by typical operator priority.

## 4. Procedures

| # | Tactic | Technique | Procedure (test or corpus id) | Telemetry | Detection | Preventive control |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Initial Access | T1190 Exploit Public-Facing Application | `test_002_search_sqli_returns_all_rows`; corpus `a03`–`a05` | `cs-uri-query` on `/search` | `csa_002` | Parameterized query |
| 2 | Collection | T1005 Data from Local System (via T1190) | `test_003_download_traversal_leaks_source`; corpus `a06`–`a08` | `cs-uri-query` on `/download` | `csa_003` | Resolved-path containment |
| 3 | Credential Access | T1606.001 Forge Web Credentials | `test_004_session_token_is_forgeable`; corpus `a09` | `token_subject`, `token_valid`, issuance lookup | `csa_004` | HMAC-signed token, constant-time verify |
| 4 | Collection | T1213 Data from Information Repositories | `test_001_idor_bob_note_readable_by_alice`; corpus `a01`–`a02` | `actor`, `resource_owner` | `csa_001` | Per-object ownership check |
| 5 | Credential Access | T1552.005 Cloud Instance Metadata API (via T1190) | `test_006_ssrf_preview_reaches_internal_config`; corpus `a12`–`a13` | `cs-uri-query` on `/preview` | `csa_006` | Scheme, host and path allowlist |
| 6 | Impact | T1565.001 Stored Data Manipulation | `test_005_negative_transfer_reverses_funds`; corpus `a10`–`a11` | `amount` on `/transfer` | `csa_005` | Type, sign and bound validation |

Tests live in [`tests/security/`](../tests/security/test_findings_vulnerable.py);
corpus ids refer to [`detections/traffic.jsonl`](../detections/traffic.jsonl).
Classification and scoring for each step are in [classification.md](classification.md).

## 5. Execution

```bash
python scripts/run_security_suites.py                             # procedures, then fixes
python -m detections.validate --output detection-report.json      # telemetry and detections
```

## 6. Results

| # | Objective reached on vulnerable build | Prevented on patched build | Detected on vulnerable | Attempt detected on patched |
| --- | --- | --- | --- | --- |
| 1 SQL injection | Yes | Yes | Yes (3/3 requests) | Yes (3/3) |
| 2 Path traversal | Yes | Yes | Yes (3/3) | Yes (3/3) |
| 3 Token forgery | Yes | Yes | Yes (1/1) | Yes (1/1) |
| 4 IDOR | Yes | Yes | Yes (2/2) | Yes (2/2) |
| 5 SSRF | Yes | Yes | Yes (2/2) | Yes (2/2) |
| 6 Negative transfer | Yes | Yes | Yes (2/2) | Yes (2/2) |

Columns 2–3 are asserted by the six exploit tests and six regression tests;
columns 4–5 by the detection replay (13 attack requests, 22 benign requests with
zero alerts). See [detections/README.md](../detections/README.md) for what that
sample does and does not establish.

## 7. Deliberate limits

- **No post-exploitation.** No command-and-control, persistence, privilege
  escalation, lateral movement, defence evasion or malware. These are prohibited
  by [AUTHORIZATION.md](../AUTHORIZATION.md) §2 and are not needed to evidence the
  attack → detect → fix loop on a single service.
- **Open book.** Defender and operator are the same person with full source
  access, so nothing here measures detection or response time under realistic
  conditions.
- **One host, synthetic data.** Findings do not transfer to any real system.

## 8. Method references

Structure borrows from publicly documented practice: MITRE ATT&CK for behaviour
naming, the MITRE Center for Threat-Informed Defense adversary emulation plan
layout (scenario, steps, procedures), NIST SP 800-115 for test phases and the
OWASP Web Security Testing Guide for web procedures. This is alignment in
structure, not a claim of certification or conformance against any of them.
