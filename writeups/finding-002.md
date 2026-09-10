# FINDING-002 — SQL Injection in `GET /search?q=`

- Severity (lab): High (full demo table readable, query logic subvertible).
- Target: local Flask demo, `vulnerable-app/app.py::search`. SQLite on localhost.
- Status: PATCHED (`remediation/patched_app.py::search`), regression-covered.

## 1. Context

Search endpoint filters notes by title substring.

## 2. Threat model

Actor: any demo user reaching the endpoint. Attack surface: the `q` query parameter concatenated into SQL. SQLite demo DB holds only synthetic notes, but the flaw class is exactly what leaks production tables in real apps.

## 3. Cause

```python
rows = conn.execute(f"SELECT id, owner, title FROM notes WHERE title LIKE '%{q}%'").fetchall()
```

f-string interpolation of untrusted input into SQL. Payload `q=' OR '1'='1` turns the filter into a tautology.

## 4. Authorized reproduction

```bash
LAB_APP_VARIANT=vulnerable pytest tests/security/test_findings_vulnerable.py::test_002_search_sqli_returns_all_rows -v
# GET /search?q=' OR '1'='1 -> 3 rows regardless of filter
```

## 5. Impact

Authentication/ownership filters bypassable; in a real DB: arbitrary row exfiltration, and with stacked queries (driver-dependent) worse. Here: all 3 synthetic rows returned.

## 6. Remediation

```python
rows = conn.execute(
    "SELECT id, owner, title FROM notes WHERE title LIKE ?",
    (f"%{q}%",),
).fetchall()
```

Parameterized query — user input stays a bound value, never SQL syntax. LIKE wildcards (`%`, `_`) in `q` are still just characters inside the bound string for matching purposes (note: literal `%` in input acts as wildcard; acceptable for a demo filter — escape with `ESCAPE` clause if exact-match semantics needed).

## 7. Regression test

`tests/regression/test_fixes.py::test_002_fixed_sqli_neutralized` — injection string returns `[]`, legitimate `shop` still matches. PASS (verified 2026-09-10).

## 8. Lessons

Never build SQL by string interpolation. Parameterize every query, even "read-only search" ones — the read path is where exfiltration happens. SAST rule to add: flag f-string/format in `execute(` calls.
