"""Run the local synthetic fixture and export inspectable JSON evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from .engine import evaluate, load_cases

def main() -> int:
    parser = argparse.ArgumentParser(description="Offline synthetic APT-like correlation")
    parser.add_argument("--output", type=Path, help="Write JSON evidence report locally")
    args = parser.parse_args()
    result = evaluate(load_cases())
    payload = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0 if result["all_expected_outcomes_met"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
