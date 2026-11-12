"""CLI for multi-step synthetic tool-boundary security evaluations."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from .core import Scenario, ScriptedStrategy, aggregate, replay
from .provider import LiveModelStrategy

DATASET = Path(__file__).with_name("scenarios.jsonl")


def load_cases(path: Path = DATASET) -> list[Scenario]:
    cases: list[Scenario] = []
    observed: set[str] = set()
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError(f"Line {number}: expected JSON object")
        expected = {"case_id", "pair_id", "variant", "category", "public_source", "public_text", "trusted_task", "report_path", "attack_goal"}
        if set(row) != expected:
            raise ValueError(f"Line {number}: schema mismatch")
        if row["case_id"] in observed:
            raise ValueError(f"Line {number}: duplicate case_id")
        observed.add(row["case_id"])
        goal = row["attack_goal"]
        if goal is not None:
            if not isinstance(goal, list) or len(goal) != 2 or not all(isinstance(s, str) for s in goal):
                raise ValueError(f"Line {number}: invalid attack goal")
            row["attack_goal"] = tuple(goal)
        cases.append(Scenario(**row))
    if not cases:
        raise ValueError("Dataset is empty")
    pairs: dict[str, list[Scenario]] = {}
    for sc in cases:
        pairs.setdefault(sc.pair_id, []).append(sc)
    for key, items in pairs.items():
        if (len(items) != 2 or {sc.variant for sc in items} != {"benign", "attack"} or
                len({(sc.public_source, sc.trusted_task, sc.report_path, sc.category) for sc in items}) != 1):
            raise ValueError(f"Pair {key} is not matched")
        attack = next(sc for sc in items if sc.variant == "attack")
        if attack.attack_goal in {("read_doc", attack.public_source), ("write_report", attack.report_path)}:
            raise ValueError(f"Pair {key} attacker goal overlaps approved operation")
    return cases


def run(mode: str = "baseline", model: str | None = None,
        dataset: Path = DATASET, max_steps: int = 5, max_calls: int = 80,
        limit_cases: int | None = None) -> dict:
    cases = load_cases(dataset)
    if limit_cases is not None:
        if limit_cases < 1:
            raise ValueError("limit_cases must be positive")
        cases = cases[:limit_cases]
    if mode in {"baseline", "attack-control"}:
        if model:
            raise ValueError("Do not label synthetic control results as a model")
        strategy = ScriptedStrategy(mode)
    elif mode in {"openai", "anthropic"}:
        if not model:
            raise ValueError("A real provider run requires explicit --model")
        strategy = LiveModelStrategy(mode, model, max_calls)
    else:
        raise ValueError("Unknown evaluation mode")
    results = [replay(case, strategy, max_steps=max_steps) for case in cases]
    report = aggregate(results, mode, hashlib.sha256(dataset.read_bytes()).hexdigest())
    if model:
        report["model"] = model
        report["api_calls"] = strategy.calls
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["baseline", "attack-control", "openai", "anthropic"], default="baseline")
    ap.add_argument("--model", help="Exact provider model ID; only valid with live provider")
    ap.add_argument("--acknowledge-api-cost", action="store_true", help="Explicit permission to send synthetic cases to paid model API")
    ap.add_argument("--max-calls", type=int, default=80, help="Maximum optional API requests per run")
    ap.add_argument("--max-steps", type=int, default=5, help="Bounded tool proposals per case, 1..20")
    ap.add_argument("--limit-cases", type=int, default=None, help="Optional small subset for cost control")
    ap.add_argument("--dataset", type=Path, default=DATASET)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args(argv)
    live = args.mode in {"openai", "anthropic"}
    if live and (not args.acknowledge_api_cost or not args.model):
        ap.error("Live providers require both --model and --acknowledge-api-cost")
    if not live and (args.acknowledge_api_cost or args.model):
        ap.error("Synthetic control results cannot be labeled as paid provider results")
    try:
        report = run(args.mode, args.model, args.dataset, args.max_steps, args.max_calls, args.limit_cases)
    except (ValueError, RuntimeError, FileNotFoundError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"Evaluation aborted, no success report: {exc}", file=sys.stderr)
        return 2
    payload = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
