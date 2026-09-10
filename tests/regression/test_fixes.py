"""Regression suite — run against the PATCHED app, all must PASS.

One test per finding. Each asserts the specific flaw is gone AND that
legitimate behaviour still works (so a fix that just breaks the endpoint
does not pass).
"""
import base64
import os

import requests

BASE = os.environ.get("LAB_BASE_URL", "http://127.0.0.1:5000")


def test_001_fixed_idor_forbidden():
    # alice must NOT read bob's note (id=3)
    r = requests.get(f"{BASE}/note/3", params={"as": "alice"}, timeout=5)
    assert r.status_code == 403, r.text
    # ...but bob still can
    r = requests.get(f"{BASE}/note/3", params={"as": "bob"}, timeout=5)
    assert r.status_code == 200
    assert r.json()["owner"] == "bob"


def test_002_fixed_sqli_neutralized():
    # injection payload is treated as a literal, matches nothing
    payload = "' OR '1'='1"
    r = requests.get(f"{BASE}/search", params={"q": payload}, timeout=5)
    assert r.status_code == 200
    assert r.json() == [], r.text
    # legitimate search still works
    r = requests.get(f"{BASE}/search", params={"q": "shopping"}, timeout=5)
    assert len(r.json()) == 1


def test_003_fixed_traversal_blocked():
    for payload in ["../app.py", "....//app.py", "../../etc/passwd", "..\\app.py"]:
        r = requests.get(f"{BASE}/download", params={"f": payload}, timeout=5)
        assert r.status_code in (400, 403, 404), payload
    # legitimate download still works
    r = requests.get(f"{BASE}/download", params={"f": "public.txt"}, timeout=5)
    assert r.status_code == 200


def test_004_fixed_session_token_not_forgeable():
    # a hand-crafted base64 token must be rejected (no valid signature)
    forged = base64.b64encode(b"bob").decode()
    r = requests.get(f"{BASE}/me", headers={"X-Session-Token": forged}, timeout=5)
    assert r.status_code == 401, r.text
    # a token issued by the server for alice works, and identifies alice
    token = requests.get(f"{BASE}/login", params={"as": "alice"}, timeout=5).json()["token"]
    r = requests.get(f"{BASE}/me", headers={"X-Session-Token": token}, timeout=5)
    assert r.status_code == 200
    assert r.json()["user"] == "alice"
    # tampering with a valid token invalidates it
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    r = requests.get(f"{BASE}/me", headers={"X-Session-Token": tampered}, timeout=5)
    assert r.status_code == 401


def test_005_fixed_negative_transfer_rejected():
    before = requests.get(f"{BASE}/balances", timeout=5).json()
    r = requests.post(f"{BASE}/transfer",
                      json={"from": "alice", "to": "bob", "amount": -50}, timeout=5)
    assert r.status_code == 400, r.text
    after = requests.get(f"{BASE}/balances", timeout=5).json()
    assert after == before, "balances must be untouched by a rejected transfer"
    # legitimate transfer still works
    r = requests.post(f"{BASE}/transfer",
                      json={"from": "alice", "to": "bob", "amount": 10}, timeout=5)
    assert r.status_code == 200
    assert r.json()["alice"] == before["alice"] - 10
    assert r.json()["bob"] == before["bob"] + 10
