import json
import os
import tempfile
import unittest
from pathlib import Path

from authzdiff.analyze import Verdict, analyze, content, has_object_reference, similarity
from authzdiff.config import DEFAULT_AUTH_HEADERS, DEFAULT_IGNORE_KEYS, Config, ConfigError, Identity, load_config
from authzdiff.models import RequestSpec, Response
from authzdiff.replay import Client, OutOfScope, build_headers


def make_config(**overrides) -> Config:
    values = dict(
        scope_hosts=("api.test",),
        owner=Identity("alice", {"Authorization": "Bearer A", "X-Tenant": "t-alice"}, ("alice@test", "José Alice", "ACME")),
        other=Identity("bob", {"Authorization": "Bearer B", "X-Tenant": "t-bob"}, ("bob@test", "ACME")),
        methods=frozenset({"GET"}),
        rate_limit=1000.0,
        timeout=5.0,
        auth_headers=DEFAULT_AUTH_HEADERS | {"x-tenant"},
        extra_headers={},
        similarity_threshold=0.95,
        ignore_keys=DEFAULT_IGNORE_KEYS,
        requests=(),
    )
    values.update(overrides)
    return Config(**values)


def reply(status=200, payload=None, raw: bytes | None = None) -> Response:
    return Response(status=status, body=raw if raw is not None else json.dumps(payload).encode())


SPEC = RequestSpec("GET", "https://api.test/orders/7")
DENIED = reply(401, {"error": "auth"})
ALICE_ORDER = {"id": 7, "email": "alice@test", "total": 10}


class VerdictTests(unittest.TestCase):
    def judge(self, owner, other, anon=DENIED, cfg=None):
        return analyze(SPEC, owner, other, anon, cfg or make_config())

    def test_owner_failure_is_skipped(self):
        self.assertIs(self.judge(reply(401, {}), reply(200, {})).verdict, Verdict.SKIPPED)
        self.assertIs(self.judge(Response(0, error="timed out"), reply(200, {})).verdict, Verdict.SKIPPED)

    def test_refusal_is_enforced(self):
        for status in (401, 403, 404):
            self.assertIs(self.judge(reply(200, ALICE_ORDER), reply(status, {"error": "no"})).verdict, Verdict.ENFORCED)

    def test_owner_marker_in_other_users_response_is_vulnerable(self):
        result = self.judge(reply(200, ALICE_ORDER), reply(200, ALICE_ORDER))
        self.assertIs(result.verdict, Verdict.VULNERABLE)
        self.assertEqual(result.leaked_to, "other")
        self.assertEqual(result.leaked_markers, ("alice@test",))

    def test_owner_marker_without_credentials_is_vulnerable(self):
        result = self.judge(reply(200, ALICE_ORDER), reply(403, {}), anon=reply(200, ALICE_ORDER))
        self.assertIs(result.verdict, Verdict.VULNERABLE)
        self.assertEqual(result.leaked_to, "anonymous")

    def test_marker_shared_by_both_accounts_proves_nothing(self):
        shared = {"company": "ACME", "plan": "pro"}
        self.assertIs(self.judge(reply(200, shared), reply(200, shared)).verdict, Verdict.SUSPECT)

    def test_same_response_behind_auth_is_suspect(self):
        data = {"id": 7, "total": 10}
        result = self.judge(reply(200, data), reply(200, data))
        self.assertIs(result.verdict, Verdict.SUSPECT)
        self.assertIn("specific object", result.reason)

    def test_same_response_without_credentials_is_public(self):
        data = {"status": "ok"}
        self.assertIs(self.judge(reply(200, data), reply(200, data), anon=reply(200, data)).verdict, Verdict.PUBLIC)

    def test_each_user_getting_own_data_differs(self):
        result = self.judge(reply(200, ALICE_ORDER), reply(200, {"id": 9, "email": "bob@test", "total": 3}))
        self.assertIs(result.verdict, Verdict.DIFFERS)

    def test_error_inside_a_200_is_not_a_leak(self):
        self.assertIs(self.judge(reply(200, ALICE_ORDER), reply(200, {"error": "forbidden"})).verdict, Verdict.DIFFERS)

    def test_volatile_keys_do_not_hide_identical_content(self):
        owner = reply(200, {"plans": ["a", "b"], "generated_at": "12:00:01", "request_id": "x1"})
        other = reply(200, {"plans": ["a", "b"], "generated_at": "12:00:02", "request_id": "x2"})
        result = self.judge(owner, other)
        self.assertIs(result.verdict, Verdict.SUSPECT)
        self.assertEqual(result.similarity_other, 1.0)

    def test_marker_matches_json_unicode_escapes(self):
        raw = b'{"name": "Jos\\u00e9 Alice", "id": 7}'
        self.assertIs(self.judge(reply(raw=raw), reply(raw=raw)).verdict, Verdict.VULNERABLE)

    def test_html_bodies_are_compared_as_text(self):
        page = b"<html><body><h1>Order 7</h1><p>alice@test</p></body></html>"
        self.assertIs(self.judge(reply(raw=page), reply(raw=page)).verdict, Verdict.VULNERABLE)
        login = b"<html><body><form>Please sign in</form></body></html>"
        self.assertIs(self.judge(reply(raw=page), reply(raw=login)).verdict, Verdict.DIFFERS)


class SimilarityTests(unittest.TestCase):
    def test_same_shape_different_values_scores_low(self):
        a = content(json.dumps({"id": 1, "name": "Alice", "email": "a@test", "role": "user"}).encode(), frozenset())
        b = content(json.dumps({"id": 2, "name": "Bob", "email": "b@test", "role": "user"}).encode(), frozenset())
        self.assertLess(similarity(a, b), 0.3)

    def test_key_order_does_not_matter(self):
        a = content(b'{"a": 1, "b": [1, 2]}', frozenset())
        b = content(b'{"b": [1, 2], "a": 1}', frozenset())
        self.assertEqual(similarity(a, b), 1.0)

    def test_empty_and_non_empty_differ(self):
        self.assertEqual(similarity(content(b"[]", frozenset()), content(b"[]", frozenset())), 1.0)
        self.assertEqual(similarity(content(b"[]", frozenset()), content(b'[{"id": 1}]', frozenset())), 0.0)

    def test_object_reference_detection(self):
        self.assertTrue(has_object_reference("https://x/api/invoices/101"))
        self.assertTrue(has_object_reference("https://x/docs/0b9d2c0e-6f1a-4c53-9a7e-2f4d8c1b7a10"))
        self.assertTrue(has_object_reference("https://x/api/report?accountId=55"))
        self.assertFalse(has_object_reference("https://x/api/v2/plans?page=2"))


class HeaderTests(unittest.TestCase):
    captured = RequestSpec(
        "GET",
        "https://api.test/orders/7",
        headers=(
            ("Authorization", "Bearer CAPTURED"), ("Cookie", "sid=CAPTURED"), ("X-Tenant", "t-alice"),
            ("Accept", "application/json"), ("Host", "api.test"), ("If-None-Match", 'W/"1"'), (":authority", "api.test"),
        ),
    )

    def test_anonymous_carries_no_credentials(self):
        headers = dict(build_headers(self.captured, None, make_config()))
        self.assertEqual(set(headers), {"Accept", "User-Agent"})

    def test_other_identity_replaces_every_credential(self):
        cfg = make_config()
        headers = dict(build_headers(self.captured, cfg.other, cfg))
        self.assertEqual(headers["Authorization"], "Bearer B")
        self.assertEqual(headers["X-Tenant"], "t-bob")
        self.assertNotIn("Cookie", headers)
        self.assertNotIn("CAPTURED", " ".join(headers.values()))

    def test_extra_headers_are_sent_for_everyone(self):
        cfg = make_config(extra_headers={"X-Bug-Bounty": "me"})
        self.assertEqual(dict(build_headers(self.captured, None, cfg))["X-Bug-Bounty"], "me")

    def test_client_refuses_out_of_scope_urls(self):
        client = Client(make_config())
        with self.assertRaises(OutOfScope):
            client.send(RequestSpec("GET", "https://elsewhere.test/"), None)
        self.assertEqual(client.sent, 0)


class ConfigTests(unittest.TestCase):
    TEMPLATE = """
[scope]
hosts = ["api.test"]
[identities.owner]
headers = { Authorization = "Bearer ${AUTHZDIFF_TEST_TOKEN}", "X-Org" = "1" }
[identities.other]
headers = { Cookie = "sid=b" }
"""

    def load(self, text: str) -> Config:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.toml"
            path.write_text(text)
            return load_config(path)

    def test_environment_variables_are_expanded(self):
        os.environ["AUTHZDIFF_TEST_TOKEN"] = "secret-value"
        self.addCleanup(os.environ.pop, "AUTHZDIFF_TEST_TOKEN", None)
        cfg = self.load(self.TEMPLATE)
        self.assertEqual(cfg.owner.headers["Authorization"], "Bearer secret-value")
        self.assertEqual(cfg.methods, frozenset({"GET"}))
        self.assertIn("x-org", cfg.auth_headers)  # identity headers count as credentials

    def test_missing_environment_variable_is_an_error(self):
        os.environ.pop("AUTHZDIFF_TEST_TOKEN", None)
        with self.assertRaisesRegex(ConfigError, "AUTHZDIFF_TEST_TOKEN"):
            self.load(self.TEMPLATE)

    def test_scope_and_both_identities_are_required(self):
        with self.assertRaisesRegex(ConfigError, "scope"):
            self.load("[identities.owner]\nheaders = { A = 'b' }\n")
        with self.assertRaisesRegex(ConfigError, "identities.other"):
            self.load("[scope]\nhosts = ['a']\n[identities.owner]\nheaders = { A = 'b' }\n")


if __name__ == "__main__":
    unittest.main()
