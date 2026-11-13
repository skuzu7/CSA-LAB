"""Offline rule checks with synthetic events.

Covers payload shapes that must never be sent on the wire from this lab (real
cloud-metadata addresses, private ranges, local schemes) plus evasions the rules
are documented NOT to catch, so a future change cannot silently alter coverage.
"""
import unittest
from pathlib import Path
from urllib.parse import urlencode

from detections.engine import load_rules
from detections.enrich import enrich

RULES = {r.finding: r for r in load_rules(Path(__file__).resolve().parents[1] / "rules")}


def web(stem: str, **params) -> dict:
    return {"cs-method": "GET", "cs-uri-stem": stem, "cs-uri-query": urlencode(params), "sc-status": 200}


def raw(stem: str, query: str) -> dict:
    return {"cs-method": "GET", "cs-uri-stem": stem, "cs-uri-query": query, "sc-status": 200}


class SsrfRule(unittest.TestCase):
    def fires(self, url: str) -> bool:
        return RULES["006"].matches(web("/preview", url=url))

    def test_internal_destinations_alert(self):
        for url in ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "http://metadata.google.internal/computeMetadata/v1/",
                    "http://10.0.0.5/admin", "http://192.168.1.1/", "http://172.16.0.9:8080/",
                    "http://172.31.255.1/", "https://127.0.0.1/", "http://[::1]:5000/internal/config",
                    "http://0.0.0.0:5000/", "http://user@127.0.0.1/", "http://a:b@10.1.2.3/",
                    "file:///etc/hostname",
                    "gopher://127.0.0.1:6379/_INFO"):
            with self.subTest(url=url):
                self.assertTrue(self.fires(url))

    def test_decoded_query_string_also_alerts(self):
        self.assertTrue(RULES["006"].matches(raw("/preview", "url=http://127.0.0.1:5000/internal/config")))

    def test_public_destinations_do_not_alert(self):
        for url in ("https://example.org/article", "http://172.32.0.1/", "http://110.20.30.40/",
                    "https://docs.example.org/metadata-guide", "https://example.org/u@10.png",
                    "https://example.org/?next=http://10.0.0.1/"):
            with self.subTest(url=url):
                self.assertFalse(self.fires(url))

    def test_other_endpoints_do_not_alert(self):
        self.assertFalse(RULES["006"].matches(web("/search", url="http://127.0.0.1/")))

    def test_documented_blind_spots_stay_documented(self):
        # Alternate IP notations and DNS names that resolve internally are prevention
        # problems (resolve-then-allowlist), not signature problems. See rule description.
        for url in ("http://2130706433/", "http://0x7f000001/", "http://internal.example.org/"):
            with self.subTest(url=url):
                self.assertFalse(self.fires(url))


class TraversalRule(unittest.TestCase):
    def test_raw_encoded_and_double_encoded_sequences_alert(self):
        for query in ("f=../app.py", "f=..%2Fapp.py", "f=..%5Capp.py", "f=%2e%2e%2fapp.py",
                      "f=..%252fapp.py", "f=....%2F%2Fapp.py", "f=..\\app.py"):
            with self.subTest(query=query):
                self.assertTrue(RULES["003"].matches(raw("/download", query)))

    def test_flat_file_names_do_not_alert(self):
        for name in ("public.txt", "report.v1.2.txt", "notes..final.txt", "a.b.c"):
            with self.subTest(name=name):
                self.assertFalse(RULES["003"].matches(web("/download", f=name)))


class SqlInjectionRule(unittest.TestCase):
    def test_injection_shapes_alert(self):
        for q in ("' OR '1'='1", "x' or 1=1 -- ", "x' UNION SELECT 1,2,3 -- ", "x';--", "x'--",
                  "x' AND (SELECT 1)=1 -- ", "x'  OR  'a'='a"):
            with self.subTest(q=q):
                self.assertTrue(RULES["002"].matches(web("/search", q=q)))

    def test_ordinary_text_does_not_alert(self):
        for q in ("o'brien", "rock or roll", "it's a to-do -- urgent", "union select committee",
                  "50% off; today", "d'orsay", "o'andrea"):
            with self.subTest(q=q):
                self.assertFalse(RULES["002"].matches(web("/search", q=q)))

    def test_documented_false_positive_and_blind_spot(self):
        # An apostrophe directly followed by the word "or" is indistinguishable by pattern.
        self.assertTrue(RULES["002"].matches(web("/search", q="rock' or roll")))
        # Numeric-context injection carries no quote and is out of scope for this rule.
        self.assertFalse(RULES["002"].matches(web("/search", q="1 OR 1=1")))


class StatefulAndApplicationRules(unittest.TestCase):
    def test_cross_owner_access_needs_both_identities(self):
        base = {"cs-method": "GET", "cs-uri-stem": "/note/3", "sc-status": 200}
        self.assertTrue(RULES["001"].matches({**base, "actor": "alice", "resource_owner": "bob"}))
        self.assertFalse(RULES["001"].matches({**base, "actor": "bob", "resource_owner": "bob"}))
        self.assertFalse(RULES["001"].matches(base))  # 404: no object, no owner recorded

    def test_negative_transfer_only(self):
        base = {"cs-method": "POST", "cs-uri-stem": "/transfer"}
        self.assertTrue(RULES["005"].matches({**base, "amount": -1}))
        self.assertFalse(RULES["005"].matches({**base, "amount": 0}))
        self.assertFalse(RULES["005"].matches({**base, "amount": None}))
        self.assertFalse(RULES["005"].matches({"cs-method": "GET", "cs-uri-stem": "/transfer", "amount": -1}))

    def test_token_enrichment_tracks_successful_issuance_in_order(self):
        stream = enrich([
            {"cs-uri-stem": "/me", "token_subject": "alice", "sc-status": 200},
            {"cs-uri-stem": "/login", "issued_subject": "alice", "sc-status": 200},
            {"cs-uri-stem": "/login", "issued_subject": "mallory", "sc-status": 401},
            {"cs-uri-stem": "/me", "token_subject": "alice", "sc-status": 200},
            {"cs-uri-stem": "/me", "token_subject": "mallory", "sc-status": 200},
            {"cs-uri-stem": "/me", "token_valid": False, "token_subject": None, "sc-status": 401},
            {"cs-uri-stem": "/me", "sc-status": 401},
        ])
        fired = [RULES["004"].matches(event) for event in stream]
        self.assertEqual(fired, [True, False, False, False, True, True, False])
        self.assertNotIn("token_issued", stream[5])


if __name__ == "__main__":
    unittest.main()
