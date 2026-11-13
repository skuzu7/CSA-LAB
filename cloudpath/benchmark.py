"""Generate machine-readable evidence from a synthetic privilege graph."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from .engine import PrivilegeGraph, key


def run_file(filename: Path) -> dict:
    raw = json.loads(filename.read_text(encoding="utf-8"))
    graph = PrivilegeGraph(raw)
    cases = []
    for query in raw.get("queries", []):
        source = query["source"]
        target = query["target"]
        paths = graph.paths(source, target)
        cut = graph.min_cut(source, target)
        after_cut = graph.paths(source, target, removed=cut)
        predicted = bool(paths)
        expected = bool(query["expected_reachable"])
        remediable = not predicted or bool(cut) and not after_cut
        cases.append({
            "source": source,
            "target": target,
            "expected_reachable": expected,
            "observed_reachable": predicted,
            "correct": predicted == expected,
            "path_count": len(paths),
            "bounded_paths": paths,
            "minimum_revocable_cut": cut,
            "remediable_with_grant_removal": remediable,
        })
    return {
        "scope": "offline-synthetic-only",
        "executes_tools": False,
        "total_cases": len(cases),
        "passed_cases": sum(int(case["correct"]) for case in cases),
        "failed_cases": sum(int(not case["correct"]) for case in cases),
        "cases": cases,
        "caveat": "Graph abstraction: not an authoritative AWS IAM or Kubernetes RBAC simulator.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path,
                        default=Path(__file__).resolve().parent / "fixtures/synthetic-org.json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run_file(args.fixture)
    serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")
    return int(result["failed_cases"] > 0)


if __name__ == "__main__":
    raise SystemExit(main())
