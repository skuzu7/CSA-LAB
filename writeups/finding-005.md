# FINDING-005 — Negative-Amount Transfer Reverses Funds in `POST /transfer`

- Severity (lab): High (integrity: attacker-chosen signed amount moves funds backwards).
- Target: local Flask demo, `vulnerable-app/app.py::transfer`, commit in this repo. Bind 127.0.0.1:5000. Balances are synthetic seed data (alice 100, bob 100).
- Status: PATCHED (`remediation/patched_app.py::transfer`), regression-covered.

## 1. Context

Demo ledger with two accounts. `POST /transfer {"from","to","amount"}` debits one and credits the other after an insufficient-funds check.

## 2. Threat model

Actor: any local client able to call the endpoint. Asset: ledger integrity. The trust boundary is the amount field; the missing control is server-side validation that the amount is a positive, bounded integer. Localhost fixture — educational, demonstrating CWE-839 / business-logic validation failure.

## 3. Cause

```python
amount = int(data.get("amount", 0))
if row["balance"] < amount:   # -50 always passes: balance >= -50
    ...
conn.execute("UPDATE accounts SET balance = balance - ? ...", (amount, src))  # minus negative = plus
```

`int()` enforces type but not sign, and the funds check is sign-blind: any balance satisfies `balance >= negative`. Subtracting a negative amount credits the source and debits the destination — the transfer runs backwards.

## 4. Authorized reproduction

```bash
LAB_APP_VARIANT=patched pytest tests/security/test_findings_vulnerable.py::test_005_negative_transfer_reverses_funds -v
# POST {"from":"alice","to":"bob","amount":-50} -> 200 {"alice":150,"bob":50}
```

Minimum PoC: `curl -X POST 127.0.0.1:5000/transfer -H 'Content-Type: application/json' -d '{"from":"alice","to":"bob","amount":-50}'`.

## 5. Impact

Attacker drains the destination account into their own with repeated negative transfers, bounded only by the victim's balance. No authentication to defeat (demo has none) and no error raised — the endpoint returns 200.

## 6. Remediation (the point of this finding)

```python
if isinstance(raw, bool) or not isinstance(raw, int):
    return jsonify({"error": "amount must be an integer"}), 400
if raw <= 0:
    return jsonify({"error": "amount must be positive"}), 400
if raw > MAX_TRANSFER:
    return jsonify({"error": "amount exceeds limit"}), 400
if src == dst:
    return jsonify({"error": "source and destination must differ"}), 400
```

Validate type, sign, and bounds *before* touching balances; reject self-transfers; verify both accounts exist. The `bool` check matters because `isinstance(True, int)` is `True` in Python. Rejected transfers leave balances untouched (asserted in the regression test).

## 7. Regression test

`tests/regression/test_fixes.py::test_005_fixed_negative_transfer_rejected` — amount -50 rejected (400), balances byte-identical before/after via `/balances`, legitimate transfer of 10 still moves funds correctly. PASS (verified 2026-09-10).

## 8. Lessons

`int()` is parsing, not validation. Business-logic invariants (amounts positive, ranges bounded, source != destination) must be enforced server-side on every state-changing endpoint — and the funds check must run against the validated value, not the raw input.
