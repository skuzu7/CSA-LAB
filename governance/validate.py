"""Fail-closed validation of the public evidence control register.

This checks evidence *references and claim types*, not actual regulatory compliance.
Run: python -m governance.validate
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTER = ROOT / "governance" / "controls.json"
STATUSES = {"demonstrated_local", "planned", "externally_verified"}


def validate_register(document: object, root: Path) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["register must be a JSON object"]
    if document.get("version") != 1 or not isinstance(document.get("controls"), list):
        return ["register must have version 1 and a controls array"]

    ids: set[str] = set()
    root = root.resolve()
    for index, control in enumerate(document["controls"]):
        ref = f"controls[{index}]"
        if not isinstance(control, dict):
            errors.append(f"{ref}: must be an object")
            continue
        control_id = control.get("id")
        if not isinstance(control_id, str) or not control_id.strip():
            errors.append(f"{ref}: non-empty id required")
        elif control_id in ids:
            errors.append(f"{ref}: duplicate id {control_id}")
        else:
            ids.add(control_id)

        status = control.get("status")
        evidence = control.get("evidence")
        limitations = control.get("limitations")
        if status not in STATUSES:
            errors.append(f"{ref}: unsupported status {status!r}")
        if not isinstance(control.get("name"), str) or not control["name"].strip():
            errors.append(f"{ref}: non-empty name required")
        if not isinstance(limitations, str) or not limitations.strip():
            errors.append(f"{ref}: explicit limitations required")
        if not isinstance(evidence, list) or not all(isinstance(x, str) for x in evidence):
            errors.append(f"{ref}: evidence must be a list of local paths")
            continue
        if status == "demonstrated_local" and not evidence:
            errors.append(f"{ref}: demonstrated control requires evidence")
        if status == "planned" and evidence:
            errors.append(f"{ref}: planned controls must not imply completed evidence")
        if status == "externally_verified":
            proof = control.get("external_verification")
            if not isinstance(proof, dict) or not all(
                isinstance(proof.get(k), str) and proof[k].strip()
                for k in ("authority", "public_url", "date")
            ):
                errors.append(f"{ref}: external verification requires authority, public_url and date")
        for path_str in evidence:
            path = Path(path_str)
            if path.is_absolute() or ".." in path.parts or not path_str.strip():
                errors.append(f"{ref}: unsafe evidence path {path_str!r}")
                continue
            resolved = (root / path).resolve()
            if not resolved.is_relative_to(root) or not resolved.is_file():
                errors.append(f"{ref}: evidence is missing or outside repository: {path_str!r}")
    return errors


def main() -> int:
    try:
        document = json.loads(REGISTER.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Invalid evidence register: {exc}")
        return 1
    failures = validate_register(document, ROOT)
    for failure in failures:
        print(f"FAIL: {failure}")
    if failures:
        return 1
    controls = document["controls"]
    states = {name: sum(x["status"] == name for x in controls) for name in STATUSES}
    print(f"Evidence register validated ({len(controls)} controls; {states})")
    print("This does not certify any organization or confirm external review.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
