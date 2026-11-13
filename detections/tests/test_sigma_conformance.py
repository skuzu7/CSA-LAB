"""Parse every rule with the reference pySigma library.

The in-repo evaluator is a small subset used for scoring. This test guards
portability instead: each rule must load in pySigma without errors (which also
enforces RE2-compatible regular expressions) and pass its offline validators.
ATT&CK tag validators are excluded because they download data at run time.
Skipped when pySigma is not installed (it is installed in CI).
"""
import unittest
from pathlib import Path

try:
    from sigma.collection import SigmaCollection
    from sigma.plugins import InstalledSigmaPlugins
    from sigma.validation import SigmaValidator
except ImportError:  # pragma: no cover - optional dependency
    SigmaCollection = None

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


@unittest.skipIf(SigmaCollection is None, "pySigma not installed")
class PySigmaConformance(unittest.TestCase):
    def test_rules_parse_and_pass_offline_validators(self):
        collection = SigmaCollection.load_ruleset([str(RULES_DIR)], collect_errors=True)
        self.assertEqual(len(collection.rules), 6)
        self.assertEqual(collection.errors, [])
        self.assertEqual([error for rule in collection.rules for error in rule.errors], [])

        validators = {name: cls for name, cls in InstalledSigmaPlugins.autodiscover().validators.items()
                      if "tag" not in name.lower() and "attack" not in name.lower()}
        self.assertGreater(len(validators), 10)
        issues = SigmaValidator(validators.values()).validate_rules(collection)
        self.assertEqual([type(issue).__name__ for issue in issues], [])


if __name__ == "__main__":
    unittest.main()
