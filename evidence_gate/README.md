# Evidence gate — auditable, no-hallucination research notes

A small offline verifier for security-research manifests. It accepts **candidate**
hypotheses without asking the researcher to invent evidence; it requires
repository-local evidence and exact SHA-256 hashes before a note can progress to
**reproduced_local** or **ready_for_human_review**.

This is a **provenance/completeness check**, not a vulnerability scanner, exploit
generator, CVE validator, authorization verifier or automatic report sender.

## Run

From repository root:

```bash
python -m unittest discover -s evidence_gate/tests -t . -v
python -m evidence_gate.verify evidence_gate/examples/candidate.json --root .
```

The second command only validates an explicitly **unverified** example.

## State gates

| Status | Required evidence | Claim permitted |
| --- | --- | --- |
| `candidate` | ID, description and limitations | A hypothesis exists; no vulnerability is asserted |
| `reproduced_local` | Above, written scope file with named target, hashed source with line, hashed local reproduction artifact and matching observed marker, command/exit code, hashed negative-control artifact | Artifacts support a locally reproduced experiment, **subject to human review** |
| `ready_for_human_review` | Above, hashed impact artifact, human-recorded duplicate-review source/date/result, eligibility notes | Completeness gate passed; reviewer must independently verify scope, impact, originality and rules |

**No automated transition to "confirmed", "CVE assigned" or "bounty accepted" exists.**

## Evidence manifest shape

```json
{
  "version": 1,
  "findings": [
    {
      "id": "LAB-001",
      "status": "candidate",
      "description": "Unverified hypothesis about a first-party test fixture",
      "limitations": "No code trace, reproduction or review yet"
    }
  ]
}
```

When progressing to `reproduced_local` or `ready_for_human_review`,
include these additional fields:

- `scope`: `{"target": "fixture-app", "authorization_file": "scope.md"}`
- `source`: `{"path": "fixture.py", "sha256": "<actual lowercase file hash>", "line": 1}`
- `reproduction`: `{"path": "logs/repro.txt", "sha256": "<actual hash>", "observed": "<marker seen in the log>", "command": "<command used>", "exit_code": 0}`
- `negative_control`: `{"path": "logs/control.txt", "sha256": "<actual hash>", "observed": "<marker seen in the log>"}`
- `impact` (ready state): `{"path": "logs/impact.txt", "sha256": "<actual hash>", "observed": "<marker seen in the log>"}`
- `duplicate_review` (ready state): human-reported `checked_on` (YYYY-MM-DD), `sources` (nonempty list), and `result` (`no_known_match`, `potential_match` or `known_match`).
- `eligibility_notes` (ready state): free-text justification/limitations.

Artifacts are **read only**. The validator runs no recorded commands and
makes no network calls. It checks that artifact hashes and observed markers
match local UTF-8 files, not whether logs are genuine or interpretations correct.
A manually entered "no known match" can never prove that a duplicate does
not exist. The check that an authorization file mentions a target is likewise
not a legal proof of consent.

Use only explicitly authorized, local or program-permitted research environments.
Retain sensitive findings and customer data in a separate private workspace:
**do not commit confidential logs, payloads, tokens or unpublished vulnerabilities**.
The synthetic fixture tests in this repository are safe examples, not real
Wordfence CVEs, external vulnerabilities or paid bounties.

## Local test acceptance criteria

The unit tests exercise at least:

- Unverified hypotheses do **not** automatically become verified findings.
- A complete *synthetic* manifest passes structural verification.
- A changed reproduction log breaks its SHA-256.
- Missing negative control fails the gate.
- A repository traversal path is rejected.
- A claimed observation absent from its hashed log is rejected.
- A known duplicate cannot pass the ready-for-review gate.
- Nonexistent source lines and invented status values are rejected.

**Human review remains required** to check target authorization, severity,
security impact, program eligibility, evidence authenticity and responsible
disclosure.
