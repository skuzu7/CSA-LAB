"""Offline benchmark runner for synthetic MCP/agent permission decisions."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from .engine import Gate


def run_suite(policy_path: Path, scenarios_path: Path) -> dict:
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    rows = []
    false_allow = false_deny = 0

    for lineno, line in enumerate(scenarios_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        scenario = json.loads(line)
        gate = Gate(policy)
        decisions = gate.evaluate(scenario["steps"])
        expected = scenario["expected"]
        if len(decisions) != len(expected):
            raise ValueError(f"Scenario {lineno} has mismatched expected vector")
        observed = [d.allowed for d in decisions]
        false_allow += sum(bool(actual) and not bool(exp) for actual, exp in zip(observed, expected))
        false_deny += sum(not bool(actual) and bool(exp) for actual, exp in zip(observed, expected))
        rows.append({
            "name": scenario["name"],
            "category": scenario["category"],
            "expected": expected,
            "observed": observed,
            "reasons": [d.reason for d in decisions],
            "passed": observed == expected,
            "audit_head": gate.audit_head,
        })

    passed = sum(int(row["passed"]) for row in rows)
    return {
        "total": len(rows),
        "passed": passed,
        "failed": len(rows) - passed,
        "false_allow": false_allow,
        "false_deny": false_deny,
        "cases": rows,
        "scope": "synthetic-offline-only",
        "executes_tools": False,
    }


def main() -> int:
    folder = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Run PolicyForge synthetic agent capability evaluation")
    parser.add_argument("--policy", type=Path, default=folder / "policy.json")
    parser.add_argument("--scenarios", type=Path, default=folder / "scenarios.jsonl")
    parser.add_argument("--output", type=Path, help="Optional JSON report path")
    args = parser.parse_args()
    result = run_suite(args.policy, args.scenarios)
    report = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report, end="")
    return 1 if result["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
