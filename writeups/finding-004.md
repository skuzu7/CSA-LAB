# FINDING-004 — Forgeable Session Token in `GET /me`

- Severity (lab): High (authentication bypass: any demo account impersonated with zero credentials).
- Target: local Flask demo, `vulnerable-app/app.py::login` + `::me`, commit in this repo. Bind 127.0.0.1:5000. Seed users alice/bob are fictional.
- Status: PATCHED (`remediation/patched_app.py::_sign` / `_verify`), regression-covered.

## 1. Context

Demo session layer: `GET /login?as=<user>` issues a token, `GET /me` (header `X-Session-Token`) returns the account for that token. No passwords — localhost fixture only.

## 2. Threat model

Actor: unauthenticated local client. Asset: any user's account view (and, chained with FINDING-005, their funds). The token is the trust boundary; the missing control is integrity — nothing binds the claimed identity to a server-held secret. Localhost fixture, so impact is educational, demonstrating CWE-565 / CWE-287 (reliance on client-controlled identity).

## 3. Cause

```python
token = base64.b64encode(user.encode()).decode()   # /login
user  = base64.b64decode(token.encode()).decode()  # /me
```

Base64 is an encoding, not a signature. The token carries the identity claim but no integrity proof, so the server cannot distinguish a token it issued from one the client fabricated.

## 4. Authorized reproduction

```bash
LAB_APP_VARIANT=vulnerable pytest tests/security/test_findings_vulnerable.py::test_004_session_token_is_forgeable -v
# GET /login?as=alice -> {"token":"YWxpY2U="}  (decodes to "alice")
# GET /me with X-Session-Token: Ym9i (base64 "bob") -> 200 {"user":"bob"}
```

Minimum PoC: `curl 127.0.0.1:5000/me -H 'X-Session-Token: Ym9i'`.

## 5. Impact

Full authentication bypass. Any account reachable by encoding its username — no rate limit to defeat, no secret to brute-force; the token space *is* the username space.

## 6. Remediation (the point of this finding)

```python
def _sign(user):
    mac = hmac.new(SESSION_KEY, user.encode(), hashlib.sha256).digest()
    return b64(user) + "." + b64(mac)

def _verify(token):
    ...
    if not hmac.compare_digest(given, expected):
        return None  # forged or tampered
    return user
```

HMAC-SHA256 over the identity claim, constant-time verification. Key from environment (in-file default explicitly labelled a lab fixture). `/login` also rejects unknown users with 401 instead of minting tokens for arbitrary strings. Deliberately out of scope: expiry, rotation, server-side session records, transport security — noted here so this is not read as a complete session design.

## 7. Regression test

`tests/regression/test_fixes.py::test_004_fixed_session_token_not_forgeable` — bare-base64 token rejected (401), tampered signature rejected (401), legitimately issued token still identifies its owner (200). PASS (verified 2026-09-10).

## 8. Lessons

Encoding is not authentication. Any client-producible value is untrusted until a server-held secret proves otherwise. The review question is not "can I read the token?" but "can I *write* one?" — if yes, there is no session layer at all.
