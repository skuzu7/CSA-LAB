"""Fail-closed, offline evidence gate for research notes.

This checks provenance and completeness of submitted artifacts. It cannot prove
that a live target is vulnerable, that an engagement is authorized, or that a
finding is original. No commands or network requests are executed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import date
from pathlib import Path

STATUSES = {"candidate", "reproduced_local", "ready_for_human_review"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
FINDING_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,79}$")


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _file(root: Path, path: object, ref: str, errors: list[str]) -> Path | None:
    if not _text(path):
        errors.append(f"{ref}: non-empty repository-relative file path required")
        return None
    p = Path(path)
    if p.is_absolute() or ".." in p.parts or "\\" in str(path):
        errors.append(f"{ref}: unsafe file path")
        return None
    resolved = (root / p).resolve()
    if not resolved.is_relative_to(root) or not resolved.is_file():
        errors.append(f"{ref}: file missing or outside repository")
        return None
    return resolved


def _artifact(root: Path, data: object, ref: str, errors: list[str]) -> str | None:
    if not isinstance(data, dict):
        errors.append(f"{ref}: artifact must include path and sha256")
        return None
    path = _file(root, data.get("path"), ref, errors)
    expected = data.get("sha256")
    if not isinstance(expected, str) or not SHA256.fullmatch(expected):
        errors.append(f"{ref}: lowercase SHA-256 required")
        return None
    if path is None:
        return None
    content = path.read_bytes()
    actual = hashlib.sha256(content).hexdigest()
    if actual != expected:
        errors.append(f"{ref}: SHA-256 mismatch")
        return None
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        errors.append(f"{ref}: UTF-8 text artifact required")
        return None


def _observed_artifact(root: Path, data: object, ref: str, errors: list[str]) -> None:
    content = _artifact(root, data, ref, errors)
    if not isinstance(data, dict):
        return
    observed = data.get("observed")
    if not _text(observed):
        errors.append(f"{ref}: observed outcome required")
    elif content is not None and observed not in content:
        errors.append(f"{ref}: observed outcome not found in hashed artifact")


def validate_manifest(document: object, root: Path) -> list[str]:
    """Return all validation errors; empty does not imply bounty eligibility."""
    if not isinstance(document, dict) or document.get("version") != 1:
        return ["manifest: object with version 1 required"]
    findings = document.get("findings")
    if not isinstance(findings, list) or not findings:
        return ["manifest: non-empty findings array required"]

    errors: list[str] = []
    ids: set[str] = set()
    root = root.resolve()
    for index, entry in enumerate(findings):
        ref = f"findings[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{ref}: finding must be an object")
            continue
        fid = entry.get("id")
        if not isinstance(fid, str) or not FINDING_ID.fullmatch(fid):
            errors.append(f"{ref}: invalid finding id")
        elif fid in ids:
            errors.append(f"{ref}: duplicate finding id")
        else:
            ids.add(fid)
        status = entry.get("status")
        if status not in STATUSES:
            errors.append(f"{ref}: unsupported status")
            continue
        for key in ("description", "limitations"):
            if not _text(entry.get(key)):
                errors.append(f"{ref}: {key} required")
        if status == "candidate":
            continue

        scope = entry.get("scope")
        if not isinstance(scope, dict) or not _text(scope.get("target")):
            errors.append(f"{ref}: scope.target required")
        else:
            scope_file = _file(root, scope.get("authorization_file"), f"{ref}.scope", errors)
            if scope_file is not None and scope["target"] not in scope_file.read_text(encoding="utf-8"):
                errors.append(f"{ref}: scope target absent from authorization file")

        source = entry.get("source")
        if not isinstance(source, dict):
            errors.append(f"{ref}: source object required")
        else:
            _artifact(root, source, f"{ref}.source", errors)
            line = source.get("line")
            if isinstance(line, bool) or not isinstance(line, int) or line < 1:
                errors.append(f"{ref}: positive source.line required")
            else:
                path = source.get("path")
                p = _file(root, path, f"{ref}.source_line", errors)
                if p is not None and line > len(p.read_text(encoding="utf-8").splitlines()):
                    errors.append(f"{ref}: source.line exceeds file length")

        reproduction = entry.get("reproduction")
        if not isinstance(reproduction, dict):
            errors.append(f"{ref}: reproduction object required")
        else:
            if not _text(reproduction.get("command")):
                errors.append(f"{ref}: reproduction.command required (record only; never executed)")
            if type(reproduction.get("exit_code")) is not int:
                errors.append(f"{ref}: reproduction.exit_code must be an integer")
            _observed_artifact(root, reproduction, f"{ref}.reproduction", errors)
        _observed_artifact(root, entry.get("negative_control"), f"{ref}.negative_control", errors)

        if status == "ready_for_human_review":
            impact = entry.get("impact")
            _observed_artifact(root, impact, f"{ref}.impact", errors)
            review = entry.get("duplicate_review")
            if not isinstance(review, dict):
                errors.append(f"{ref}: duplicate_review object required")
            else:
                try:
                    date.fromisoformat(review.get("checked_on", ""))
                except (TypeError, ValueError):
                    errors.append(f"{ref}: duplicate_review.checked_on requires YYYY-MM-DD")
                sources = review.get("sources")
                if not isinstance(sources, list) or not sources or not all(_text(x) for x in sources):
                    errors.append(f"{ref}: duplicate_review.sources required")
                if review.get("result") not in {"no_known_match", "potential_match", "known_match"}:
                    errors.append(f"{ref}: duplicate_review.result required")
                if review.get("result") != "no_known_match":
                    errors.append(f"{ref}: potential/known duplicate cannot be ready for review")
            if not _text(entry.get("eligibility_notes")):
                errors.append(f"{ref}: eligibility_notes required")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="trusted local workspace root")
    args = parser.parse_args()
    try:
        document = json.loads(args.manifest.read_text(encoding="utf-8"))
        errors = validate_manifest(document, args.root)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"FAIL: unreadable manifest: {exc}")
        return 1
    for item in errors:
        print(f"FAIL: {item}")
    if errors:
        return 1
    print("PASS: evidence structure and local artifact hashes validated")
    print("NOT VERIFIED: authorization authenticity, runtime behavior, originality, impact, bounty eligibility")
    print("Human review and explicit permission remain mandatory; no reports were submitted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
