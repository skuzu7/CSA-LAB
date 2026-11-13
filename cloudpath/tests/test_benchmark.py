"""Evidence contract for synthetic privilege graph benchmark."""
import unittest
from pathlib import Path
from cloudpath.benchmark import run_file

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic-org.json"


class BenchmarkTests(unittest.TestCase):
    def test_expected_paths_and_blocked_identity(self):
        report = run_file(FIXTURE)
        self.assertEqual(report["total_cases"], 3)
        self.assertEqual(report["passed_cases"], 3)
        self.assertEqual(report["failed_cases"], 0)
        self.assertTrue(report["cases"][0]["remediable_with_grant_removal"])
        self.assertFalse(report["cases"][1]["observed_reachable"])

    def test_report_never_executes_permissions(self):
        report = run_file(FIXTURE)
        self.assertFalse(report["executes_tools"])
        self.assertEqual(report["scope"], "offline-synthetic-only")


if __name__ == "__main__":
    unittest.main()
