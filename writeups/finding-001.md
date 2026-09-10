# FINDING-001 — Broken Object-Level Authorization (IDOR) in `GET /note/<id>`

- Severity (lab): High (confidentiality: any demo user reads any note).
- Target: local Flask demo, `vulnerable-app/app.py::get_note`, commit in this repo. Bind 127.0.0.1:5000. Seed users alice/bob are fictional.
- Status: PATCHED (`remediation/patched_app.py::get_note`), regression-covered.

## 1. Context

Notes app with per-user notes. Demo auth via `?as=<user>`. `GET /note/<id>` looked up the row by id only.

## 2. Threat model

Actor: authenticated demo user (alice). Asset: other users' note bodies. The endpoint is the trust boundary; the missing control is an ownership check. No network exposure — localhost fixture — so impact here is educational, demonstrating the exact flaw class (API1:2023 Broken Object Level Authorization).

## 3. Cause

```python
row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
# ... returns row with no `row["owner"] == current_user()` check
```

Authorization was assumed from authentication ("logged in, so allowed") instead of enforced per object.

## 4. Authorized reproduction

```bash
LAB_APP_VARIANT=vulnerable pytest tests/security/test_findings_vulnerable.py::test_001_idor_bob_note_readable_by_alice -v
# GET /note/3?as=alice -> 200 {"owner": "bob", ...}
```

Minimum PoC: `curl "http://127.0.0.1:5000/note/3?as=alice"`.

## 5. Impact

Any demo user reads any note by id enumeration. In a real app this is a confidentiality breach; here it is contained to synthetic seed data on localhost.

## 6. Remediation (the point of this finding)

```python
if row["owner"] != current_user():
    abort(403)
```

Owner check on every object access, fail-closed (404 unknown, 403 known-but-not-yours — no id oracle beyond what the app already leaks). Defense in depth: per-user query scoping (`WHERE id=? AND owner=?`) is equivalent; centralized authorization helper recommended for larger apps.

## 7. Regression test

`tests/regression/test_fixes.py::test_001_fixed_idor_forbidden` — alice gets 403 on bob's note, 200 on her own. PASS (verified 2026-09-10).

## 8. Lessons

Access control must be enforced server-side per object, never inferred from login state. BOLA remains OWASP API #1 because the fix is one `if` that is easy to forget on every new endpoint — hence regression tests per endpoint, not just per app.
