"""Offline tests for fail-closed security evidence verification."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from evidence_gate.verify import validate_manifest


def ref(root, name, content):
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return {"path": name, "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()}


class EvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def ready(self):
        ref(self.root, "scope.md", "Authorized local fixture: fixture-app. Synthetic data only.")
        source = ref(self.root, "fixture.py", "def demo():\n    return 'lab'\n")
        reproduction = ref(self.root, "logs/reproduction.txt", "LOCAL_REPRODUCED via synthetic fixture\n")
        control = ref(self.root, "logs/control.txt", "CONTROL_BLOCKED on patched fixture\n")
        impact = ref(self.root, "logs/impact.txt", "SYNTHETIC_IMPACT confirmed in local data\n")
        return {"version": 1, "findings": [{
            "id": "LAB-001",
            "status": "ready_for_human_review",
            "description": "Synthetic example only, not an external finding.",
            "limitations": "Lab demonstration is not real-world validation.",
            "scope": {"target": "fixture-app", "authorization_file": "scope.md"},
            "source": {**source, "line": 1},
            "reproduction": {**reproduction, "observed": "LOCAL_REPRODUCED",
                             "command": "python -m unittest", "exit_code": 0},
            "negative_control": {**control, "observed": "CONTROL_BLOCKED"},
            "impact": {**impact, "observed": "SYNTHETIC_IMPACT"},
            "duplicate_review": {
                "checked_on": "2026-11-19",
                "sources": ["local fixture inventory"],
                "result": "no_known_match",
            },
            "eligibility_notes": "Local-only example: not eligible for any third-party program",
        }]}

    def test_candidate_without_evidence_is_allowed_but_not_verified(self):
        candidate = {"version": 1, "findings": [{
            "id": "LAB-002", "status": "candidate",
            "description": "Unverified hypothesis", "limitations": "No experiment performed"
        }]}
        self.assertEqual(validate_manifest(candidate, self.root), [])

    def test_ready_with_matching_hashed_artifacts(self):
        self.assertEqual(validate_manifest(self.ready(), self.root), [])

    def test_rejects_tampered_log(self):
        document = self.ready()
        (self.root / "logs/reproduction.txt").write_text("TAMPERED", encoding="utf-8")
        errors = validate_manifest(document, self.root)
        self.assertTrue(any("SHA-256 mismatch" in x for x in errors), errors)

    def test_rejects_missing_negative_control(self):
        document = self.ready()
        document["findings"][0].pop("negative_control")
        self.assertTrue(any("negative_control" in x for x in validate_manifest(document, self.root)))

    def test_rejects_out_of_scope_path(self):
        document = self.ready()
        document["findings"][0]["source"]["path"] = "../outside.py"
        self.assertTrue(any("unsafe file path" in x for x in validate_manifest(document, self.root)))

    def test_rejects_unconfirmed_observation(self):
        document = self.ready()
        document["findings"][0]["reproduction"]["observed"] = "NOT_IN_LOG"
        self.assertTrue(any("not found in hashed artifact" in x for x in validate_manifest(document, self.root)))

    def test_rejects_known_duplicate(self):
        document = self.ready()
        document["findings"][0]["duplicate_review"]["result"] = "known_match"
        self.assertTrue(any("cannot be ready for review" in x for x in validate_manifest(document, self.root)))

    def test_rejects_invalid_line_and_unverified_status(self):
        document = self.ready()
        document["findings"][0]["source"]["line"] = 999
        self.assertTrue(any("exceeds file length" in x for x in validate_manifest(document, self.root)))
        document["findings"][0]["status"] = "confirmed"
        self.assertTrue(any("unsupported status" in x for x in validate_manifest(document, self.root)))


if __name__ == "__main__":
    unittest.main()
