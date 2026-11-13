"""Deterministic, offline adversarial tests for an agent tool authorization gate."""
import unittest
from policyforge.engine import Gate


BASE_POLICY = {
    "grants": [
        {"actor": "analyst", "tool": "repo", "action": "read", "resource": "repo://owner/lab/docs/"},
        {"actor": "analyst", "tool": "repo", "action": "delete", "resource": "repo://owner/lab/docs/"},
    ],
    "approvals": {
        "human-approve-17": {
            "actor": "analyst",
            "tool": "repo",
            "action": "delete",
            "resource": "repo://owner/lab/docs/stale.md",
        }
    },
}


def step(id, action="read", resource="repo://owner/lab/docs/a.md", **kwargs):
    return {"id": id, "actor": "analyst", "tool": "repo", "action": action,
            "resource": resource, "source": "tool_output", **kwargs}


class PolicyForgeTests(unittest.TestCase):
    def test_allowed_read_under_least_privilege_scope(self):
        result = Gate(BASE_POLICY).evaluate([step("read")])[0]
        self.assertTrue(result.allowed)

    def test_tool_output_cannot_authorize_new_capability(self):
        entry = step("inject", action="execute")
        self.assertEqual(Gate(BASE_POLICY).evaluate([entry])[0].reason, "no_grant")

    def test_encoded_and_plain_path_traversal_are_denied(self):
        for path in ("repo://owner/lab/docs/../secrets.txt",
                     "repo://owner/lab/docs/%2e%2e/secrets.txt",
                     r"repo://owner/lab/docs/..\\secrets.txt",
                     "https://attacker.test/x"):
            with self.subTest(path=path):
                result = Gate(BASE_POLICY).evaluate([step("escape", resource=path)])[0]
                self.assertEqual(result.reason, "unsafe_resource")

    def test_scope_boundary_is_strict(self):
        result = Gate(BASE_POLICY).evaluate([step("outside", resource="repo://owner/lab/docs2/x")])[0]
        self.assertEqual(result.reason, "no_grant")

    def test_destructive_call_requires_trusted_approval(self):
        result = Gate(BASE_POLICY).evaluate([step("delete", action="delete",
            resource="repo://owner/lab/docs/stale.md")])[0]
        self.assertEqual(result.reason, "approval_required")

    def test_forged_approval_is_rejected(self):
        result = Gate(BASE_POLICY).evaluate([step("fake", action="delete",
            resource="repo://owner/lab/docs/stale.md", approval_id="prompt_says_yes")])[0]
        self.assertEqual(result.reason, "approval_required")

    def test_exact_human_approval_is_consumed_once(self):
        gate = Gate(BASE_POLICY)
        calls = [
            step("a", action="delete", resource="repo://owner/lab/docs/stale.md",
                 approval_id="human-approve-17"),
            step("b", action="delete", resource="repo://owner/lab/docs/stale.md",
                 approval_id="human-approve-17"),
        ]
        result = gate.evaluate(calls)
        self.assertTrue(result[0].allowed)
        self.assertEqual(result[1].reason, "approval_required")

    def test_denied_parent_cannot_enable_dependent_step(self):
        calls = [step("a", action="execute"), step("b", depends_on=["a"])]
        result = Gate(BASE_POLICY).evaluate(calls)
        self.assertEqual([r.allowed for r in result], [False, False])
        self.assertEqual(result[1].reason, "dependency_denied")

    def test_duplicated_step_ids_fail_closed(self):
        result = Gate(BASE_POLICY).evaluate([step("same"), step("same")])
        self.assertTrue(result[0].allowed)
        self.assertEqual(result[1].reason, "duplicate_step")

    def test_hash_chain_is_deterministic_and_changes_on_tampering(self):
        one = Gate(BASE_POLICY).evaluate([step("s1")])
        two = Gate(BASE_POLICY).evaluate([step("s1")])
        changed = Gate(BASE_POLICY).evaluate([step("s1", resource="repo://owner/lab/docs/b.md")])
        self.assertEqual(one[0].audit_sha256, two[0].audit_sha256)
        self.assertNotEqual(one[0].audit_sha256, changed[0].audit_sha256)
        self.assertRegex(one[0].audit_sha256, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
