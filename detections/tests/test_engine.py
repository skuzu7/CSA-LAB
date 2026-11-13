"""Unit tests for the Sigma-subset evaluator (no network, no fixture)."""
import unittest
from pathlib import Path

from detections.engine import Rule, UnsupportedRule, _Condition, load_rules


def rule(detection: dict) -> Rule:
    return Rule(path=Path("inline.yml"), doc={"id": "x", "title": "t", "detection": detection})


class ValueMatching(unittest.TestCase):
    def test_equality_is_case_insensitive_and_supports_wildcards(self):
        r = rule({"sel": {"cs-method": "post", "cs-uri-stem": "/note/*"}, "condition": "sel"})
        self.assertTrue(r.matches({"cs-method": "POST", "cs-uri-stem": "/note/3"}))
        self.assertFalse(r.matches({"cs-method": "POST", "cs-uri-stem": "/search"}))

    def test_value_list_is_or_and_all_modifier_is_and(self):
        any_of = rule({"sel": {"q|contains": ["aa", "bb"]}, "condition": "sel"})
        all_of = rule({"sel": {"q|contains|all": ["aa", "bb"]}, "condition": "sel"})
        self.assertTrue(any_of.matches({"q": "xxAAxx"}))
        self.assertFalse(all_of.matches({"q": "xxAAxx"}))
        self.assertTrue(all_of.matches({"q": "bb-aa"}))

    def test_startswith_endswith_and_regex_flag(self):
        r = rule({"a": {"p|startswith": "/no"}, "b": {"p|endswith": "TE/3"},
                  "c": {"p|re": "NOTE"}, "d": {"p|re|i": "NOTE"}, "condition": "a and b and d and not c"})
        self.assertTrue(r.matches({"p": "/note/3"}))

    def test_numeric_comparisons_ignore_non_numbers_and_booleans(self):
        r = rule({"sel": {"amount|lt": 0}, "condition": "sel"})
        self.assertTrue(r.matches({"amount": -1}))
        self.assertFalse(r.matches({"amount": 0}))
        self.assertFalse(r.matches({"amount": "-5"}))
        self.assertFalse(r.matches({"amount": False}))
        self.assertFalse(r.matches({}))

    def test_boolean_and_null_and_exists(self):
        r = rule({"f": {"token_valid": False}, "n": {"token_subject": None},
                  "e": {"actor|exists": True}, "condition": "f and n and e"})
        self.assertTrue(r.matches({"token_valid": False, "token_subject": None, "actor": "alice"}))
        self.assertFalse(r.matches({"token_valid": 0, "actor": "alice"}))
        self.assertFalse(r.matches({"token_valid": False, "token_subject": "bob", "actor": "alice"}))
        self.assertFalse(r.matches({"token_valid": False}))

    def test_fieldref_compares_two_fields_and_requires_both(self):
        r = rule({"same": {"actor|fieldref": "resource_owner"}, "condition": "not same"})
        self.assertTrue(r.matches({"actor": "alice", "resource_owner": "bob"}))
        self.assertFalse(r.matches({"actor": "Alice", "resource_owner": "alice"}))
        self.assertTrue(r.matches({"actor": "alice"}))

    def test_list_of_maps_is_or(self):
        r = rule({"sel": [{"a": 1}, {"b": 2}], "condition": "sel"})
        self.assertTrue(r.matches({"b": 2}))
        self.assertFalse(r.matches({"a": 2, "b": 1}))


class Conditions(unittest.TestCase):
    RESULTS = {"sel_a": True, "sel_b": False, "filter_x": False}

    def check(self, text: str) -> bool:
        return _Condition(text, dict(self.RESULTS)).evaluate()

    def test_precedence_not_binds_tighter_than_and_than_or(self):
        self.assertTrue(self.check("sel_a and not filter_x"))
        self.assertTrue(self.check("sel_b or sel_a and not filter_x"))
        self.assertFalse(self.check("(sel_b or sel_a) and filter_x"))
        self.assertTrue(self.check("not (sel_b or filter_x)"))

    def test_quantifiers(self):
        self.assertTrue(self.check("1 of sel_*"))
        self.assertFalse(self.check("all of sel_*"))
        self.assertTrue(self.check("1 of them"))
        self.assertFalse(self.check("all of them"))

    def test_unsupported_or_malformed_conditions_fail_closed(self):
        for text in ("sel_a | count() > 5", "sel_a and", "sel_a sel_b", "(sel_a", "unknown",
                     "1 of nothing_*", "sel_a && sel_b"):
            with self.subTest(text=text), self.assertRaises(UnsupportedRule):
                self.check(text)


class FailClosed(unittest.TestCase):
    def test_unknown_modifier_and_keyword_search_are_rejected(self):
        with self.assertRaises(UnsupportedRule):
            rule({"sel": {"q|base64offset|contains": "x"}, "condition": "sel"}).matches({"q": "x"})
        with self.assertRaises(UnsupportedRule):
            rule({"sel": ["free text"], "condition": "sel"}).matches({"q": "x"})

    def test_repository_rules_load_with_unique_ids_and_one_rule_per_finding(self):
        rules = load_rules(Path(__file__).resolve().parents[1] / "rules")
        self.assertEqual(sorted(r.finding for r in rules), ["001", "002", "003", "004", "005", "006"])
        self.assertEqual(len({r.rule_id for r in rules}), 6)


if __name__ == "__main__":
    unittest.main()
