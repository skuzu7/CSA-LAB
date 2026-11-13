"""Synthetic benchmark acceptance checks."""
import unittest
from pathlib import Path
from policyforge.benchmark import run_suite


ROOT = Path(__file__).resolve().parents[1]


class BenchmarkTests(unittest.TestCase):
    def test_all_benign_and_adversarial_scenarios_match_policy(self):
        report = run_suite(ROOT / "policy.json", ROOT / "scenarios.jsonl")
        self.assertGreaterEqual(report["total"], 9)
        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["false_allow"], 0)
        self.assertEqual(report["false_deny"], 0)
        self.assertEqual(report["passed"], report["total"])

    def test_audit_digests_present_without_tool_execution(self):
        report = run_suite(ROOT / "policy.json", ROOT / "scenarios.jsonl")
        self.assertTrue(all(len(row["audit_head"]) == 64 for row in report["cases"]))


if __name__ == "__main__":
    unittest.main()
