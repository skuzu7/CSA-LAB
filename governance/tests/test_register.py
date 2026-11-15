"""Adversarial tests for claim provenance, not for compliance certification."""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from governance.validate import REGISTER, ROOT, validate_register


class ControlRegisterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.real_document = json.loads(REGISTER.read_text(encoding="utf-8"))

    def test_current_register_resolves_all_demonstrated_evidence(self) -> None:
        self.assertEqual(validate_register(self.real_document, ROOT), [])

    def test_rejects_missing_evidence_for_claimed_control(self) -> None:
        fixture = copy.deepcopy(self.real_document)
        fixture["controls"][0]["evidence"] = []
        self.assertTrue(validate_register(fixture, ROOT))

    def test_rejects_evidence_path_traversal(self) -> None:
        fixture = copy.deepcopy(self.real_document)
        fixture["controls"][0]["evidence"] = ["../../private.txt"]
        self.assertTrue(validate_register(fixture, ROOT))

    def test_rejects_missing_local_files(self) -> None:
        fixture = copy.deepcopy(self.real_document)
        fixture["controls"][0]["evidence"] = ["governance/this-does-not-exist.md"]
        self.assertTrue(validate_register(fixture, ROOT))

    def test_rejects_duplicate_ids(self) -> None:
        fixture = copy.deepcopy(self.real_document)
        fixture["controls"][1]["id"] = fixture["controls"][0]["id"]
        self.assertTrue(validate_register(fixture, ROOT))

    def test_rejects_fake_external_attestation(self) -> None:
        fixture = copy.deepcopy(self.real_document)
        fixture["controls"][0]["status"] = "externally_verified"
        self.assertTrue(validate_register(fixture, ROOT))

    def test_planned_cannot_be_disguised_as_completed(self) -> None:
        fixture = copy.deepcopy(self.real_document)
        planned = next(x for x in fixture["controls"] if x["status"] == "planned")
        planned["evidence"] = ["README.md"]
        self.assertTrue(validate_register(fixture, ROOT))

    def test_symlink_outside_repository_cannot_be_evidence(self) -> None:
        with TemporaryDirectory() as temp:
            workspace = Path(temp) / "repo"
            workspace.mkdir()
            secret = Path(temp) / "private"
            secret.write_text("synthetic test data", encoding="utf-8")
            try:
                (workspace / "escaped.txt").symlink_to(secret)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks unavailable")
            fixture = {"version": 1, "controls": [{
                "id": "TEST", "name": "Test", "status": "demonstrated_local",
                "evidence": ["escaped.txt"], "limitations": "Synthetic only"
            }]}
            self.assertTrue(validate_register(fixture, workspace))


if __name__ == "__main__":
    unittest.main()
