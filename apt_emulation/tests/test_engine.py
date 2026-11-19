"""Deterministic tests for the purely synthetic threat-emulation scenario."""

import copy
import unittest
from apt_emulation.engine import STAGES, detect_case, evaluate, load_cases, validate_cases

class EmulationTests(unittest.TestCase):
    def setUp(self):
        self.cases = load_cases()
        self.positive = next(case for case in self.cases if case["expected_alert"])

    def test_documented_scenarios_have_expected_outcomes(self):
        report = evaluate(self.cases)
        self.assertTrue(report["all_expected_outcomes_met"])
        self.assertEqual(report["confusion_matrix"], {
            "true_positive": 1, "true_negative": 5,
            "false_positive": 0, "false_negative": 0,
        })

    def test_synthetic_chain_maps_all_seven_techniques(self):
        result = detect_case(self.positive)
        self.assertTrue(result["alert"])
        self.assertEqual(result["techniques"], [item[1] for item in STAGES])
        self.assertEqual(len(result["matched_timestamps"]), 7)

    def test_no_stage_can_be_omitted(self):
        for index in range(7):
            variant = copy.deepcopy(self.positive)
            del variant["events"][index]
            self.assertFalse(detect_case(variant)["alert"], f"stage {index} was optional")

    def test_technique_ids_must_match_events(self):
        variant = copy.deepcopy(self.positive)
        variant["events"][2]["technique"] = "T1082"
        self.assertFalse(detect_case(variant)["alert"])

    def test_separate_actors_are_not_mixed(self):
        variant = copy.deepcopy(self.positive)
        variant["events"][5]["actor"] = "someone-else"
        self.assertFalse(detect_case(variant)["alert"])

    def test_separate_campaigns_are_not_mixed(self):
        variant = copy.deepcopy(self.positive)
        variant["events"][5]["campaign"] = "other-campaign"
        self.assertFalse(detect_case(variant)["alert"])

    def test_time_window_limits_correlation(self):
        self.assertFalse(detect_case(self.positive, window_seconds=30)["alert"])
        self.assertTrue(detect_case(self.positive, window_seconds=1800)["alert"])

    def test_non_synthetic_telemetry_is_rejected(self):
        variant = copy.deepcopy(self.positive)
        variant["events"][0]["synthetic"] = False
        with self.assertRaises(ValueError):
            validate_cases([variant])

    def test_naive_timestamp_is_rejected(self):
        variant = copy.deepcopy(self.positive)
        variant["events"][0]["timestamp"] = "2026-01-01T12:00:00"
        with self.assertRaises(ValueError):
            detect_case(variant)

    def test_duplicate_case_id_is_rejected(self):
        with self.assertRaises(ValueError):
            evaluate([self.positive, copy.deepcopy(self.positive)])

if __name__ == "__main__":
    unittest.main()
