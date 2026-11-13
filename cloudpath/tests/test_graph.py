"""Offline IAM/Kubernetes privilege path simulation, no cloud credentials required."""
import unittest

from cloudpath.engine import PrivilegeGraph


def graph():
    return PrivilegeGraph({
        "nodes": [
            {"id": "principal:dev", "kind": "principal"},
            {"id": "role:build", "kind": "role"},
            {"id": "role:admin", "kind": "role"},
            {"id": "resource:secrets", "kind": "resource"},
            {"id": "principal:blocked", "kind": "principal"},
        ],
        "edges": [
            {"from": "principal:dev", "to": "role:build", "action": "sts:AssumeRole", "revocable": True},
            {"from": "role:build", "to": "role:admin", "action": "iam:PassRole", "revocable": True},
            {"from": "role:admin", "to": "resource:secrets", "action": "secretsmanager:GetSecretValue", "revocable": True},
            {"from": "principal:blocked", "to": "role:admin", "action": "sts:AssumeRole", "condition_met": False},
        ]
    })


class GraphTests(unittest.TestCase):
    def test_cross_role_privilege_path(self):
        paths = graph().paths("principal:dev", "resource:secrets")
        self.assertEqual(len(paths), 1)
        self.assertEqual([edge["action"] for edge in paths[0]],
                         ["sts:AssumeRole", "iam:PassRole", "secretsmanager:GetSecretValue"])

    def test_condition_not_met_blocks_path(self):
        self.assertEqual(graph().paths("principal:blocked", "resource:secrets"), [])

    def test_nonexistent_resource_rejected(self):
        with self.assertRaises(ValueError):
            graph().paths("principal:dev", "resource:not-found")

    def test_minimal_cut_removes_all_paths(self):
        g = graph()
        cut = g.min_cut("principal:dev", "resource:secrets")
        self.assertEqual(len(cut), 1)
        self.assertEqual(len(g.paths("principal:dev", "resource:secrets", removed=cut)), 0)

    def test_parallel_paths_require_two_denials(self):
        data = {
            "nodes": [{"id": x, "kind": "role"} for x in ("start", "a", "b", "target")],
            "edges": [
                {"from": "start", "to": "a", "action": "assume", "revocable": True},
                {"from": "start", "to": "b", "action": "assume", "revocable": True},
                {"from": "a", "to": "target", "action": "read", "revocable": True},
                {"from": "b", "to": "target", "action": "read", "revocable": True},
            ]
        }
        g = PrivilegeGraph(data)
        self.assertEqual(len(g.paths("start", "target")), 2)
        cut = g.min_cut("start", "target")
        self.assertEqual(len(cut), 2)
        self.assertEqual(g.paths("start", "target", removed=cut), [])

    def test_explicit_deny_overrides_allow(self):
        data = {
            "nodes": [{"id": x, "kind": "role"} for x in ("start", "end")],
            "edges": [
                {"from": "start", "to": "end", "action": "read", "effect": "Allow"},
                {"from": "start", "to": "end", "action": "read", "effect": "Deny"},
            ]
        }
        self.assertEqual(PrivilegeGraph(data).paths("start", "end"), [])

    def test_unrevocable_path_detected_without_false_remediation(self):
        data = {
            "nodes": [{"id": x, "kind": "role"} for x in ("start", "end")],
            "edges": [{"from": "start", "to": "end", "action": "read", "revocable": False}]
        }
        g = PrivilegeGraph(data)
        self.assertEqual(len(g.paths("start", "end")), 1)
        self.assertEqual(g.min_cut("start", "end"), [])

    def test_malformed_graph_denied(self):
        with self.assertRaises(ValueError):
            PrivilegeGraph({"nodes": [{"id": "x", "kind": "role"}], "edges": [
                {"from": "x", "to": "unknown", "action": "read"}
            ]})

    def test_bounds_prevent_unbounded_enumeration(self):
        g = graph()
        with self.assertRaises(ValueError):
            g.paths("principal:dev", "resource:secrets", max_hops=100000)

    def test_reproducible_deterministic_paths(self):
        g = graph()
        self.assertEqual(g.paths("principal:dev", "resource:secrets"),
                         g.paths("principal:dev", "resource:secrets"))


if __name__ == "__main__":
    unittest.main()
