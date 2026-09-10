"""Regression suite — run against the PATCHED app, all must PASS."""
import os
import requests

BASE = os.environ.get("LAB_BASE_URL", "http://127.0.0.1:5000")


def test_001_fixed_idor_forbidden():
    r = requests.get(f"{BASE}/note/3", params={"as": "alice"}, timeout=5)
    assert r.status_code == 403
    r2 = requests.get(f"{BASE}/note/1", params={"as": "alice"}, timeout=5)
    assert r2.status_code == 200 and r2.json()["owner"] == "alice"


def test_002_fixed_sqli_neutralized():
    r = requests.get(f"{BASE}/search", params={"q": "' OR '1'='1", "as": "alice"}, timeout=5)
    assert r.status_code == 200
    assert r.json() == [], "payload must be treated as a literal string"
    r2 = requests.get(f"{BASE}/search", params={"q": "shop", "as": "alice"}, timeout=5)
    assert any("shopping" in n["title"] for n in r2.json())


def test_003_fixed_traversal_blocked():
    for payload in ["../app.py", "..%2Fapp.py", "....//app.py", "/etc/hosts"]:
        r = requests.get(f"{BASE}/download", params={"f": payload}, timeout=5)
        assert r.status_code in (400, 403, 404), payload
    r = requests.get(f"{BASE}/download", params={"f": "public.txt"}, timeout=5)
    assert r.status_code == 200 and "public file" in r.text
