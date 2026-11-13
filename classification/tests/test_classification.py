"""CVSS calculator checks and integrity of the finding classification data."""
import json
import re
import unittest
from pathlib import Path

import yaml

from classification import render
from classification.cvss31 import parse, roundup, score

ROOT = Path(__file__).resolve().parents[2]
DATA = json.loads((ROOT / "classification" / "findings.json").read_text(encoding="utf-8"))

# Published reference scores for well-known vectors (FIRST calculator / NVD).
REFERENCE = {
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 8.8,
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H": 8.1,
    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 6.5,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N": 5.4,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N": 5.3,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
}


class Cvss31(unittest.TestCase):
    def test_reference_vectors(self):
        for vector, expected in REFERENCE.items():
            with self.subTest(vector=vector):
                self.assertEqual(score(vector).base, expected)

    def test_roundup_follows_the_specification(self):
        self.assertEqual(roundup(4.0), 4.0)
        self.assertEqual(roundup(4.02), 4.1)
        self.assertEqual(roundup(4.000001), 4.0)  # floating-point noise must not round up
        self.assertEqual(roundup(9.99), 10.0)

    def test_severity_bands(self):
        bands = {0.0: "None", 5.3: "Medium", 7.5: "High", 9.8: "Critical"}
        for vector, base in REFERENCE.items():
            if base in bands:
                self.assertEqual(score(vector).severity, bands[base])

    def test_malformed_vectors_are_rejected(self):
        for vector in ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                       "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
                       "CVSS:3.1/AC:L/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H",
                       "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P"):
            with self.subTest(vector=vector), self.assertRaises(ValueError):
                parse(vector)


class FindingData(unittest.TestCase):
    def test_six_findings_with_expected_scores(self):
        scores = {f["id"]: score(f["cvss"]).base for f in DATA["findings"]}
        self.assertEqual(scores, {"001": 6.5, "002": 7.5, "003": 7.5, "004": 7.5, "005": 7.5, "006": 8.6})

    def test_every_reference_resolves_to_real_evidence(self):
        for f in DATA["findings"]:
            with self.subTest(finding=f["id"]):
                writeup = (ROOT / "writeups" / f"finding-{f['id']}.md").read_text(encoding="utf-8")
                self.assertIn(f"CVSS v3.1 **{score(f['cvss']).base:.1f} ({score(f['cvss']).severity})** `{f['cvss']}`", writeup)
                for key in ("poc", "regression"):
                    path, _, name = f[key].partition("::")
                    self.assertIn(f"def {name}(", (ROOT / path).read_text(encoding="utf-8"))
                rule = yaml.safe_load((ROOT / f["detection"]).read_text(encoding="utf-8"))
                self.assertEqual(rule["csa_lab_finding"], f["id"])
                tagged = {t.split(".", 1)[1].upper() for t in rule["tags"] if re.match(r"attack\.t\d", t)}
                self.assertEqual(tagged, {t["id"] for t in f["attack"]})
                for cwe in f["cwe"]:
                    self.assertRegex(cwe, r"^CWE-\d+$")
                for mitigation in f["mitigations"]:
                    self.assertIn(mitigation, DATA["mitigation_names"])

    def test_published_page_matches_the_data(self):
        self.assertEqual(render.main(["--check"]), 0)


if __name__ == "__main__":
    unittest.main()
