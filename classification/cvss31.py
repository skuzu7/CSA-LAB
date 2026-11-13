"""CVSS v3.1 base-score calculator (FIRST specification, section 7).

Standard library only. Used to derive every score published in this repository
from its vector string, so no severity number is typed by hand.

    python -m classification.cvss31 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
"""
from __future__ import annotations

import math
import sys
from dataclasses import dataclass

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PRIVILEGES = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


@dataclass(frozen=True)
class Score:
    vector: str
    iss: float
    impact: float
    exploitability: float
    base: float

    @property
    def severity(self) -> str:
        if self.base == 0:
            return "None"
        if self.base < 4:
            return "Low"
        if self.base < 7:
            return "Medium"
        return "High" if self.base < 9 else "Critical"


def roundup(value: float) -> float:
    """Spec-defined Roundup: smallest number with one decimal >= value."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def parse(vector: str) -> dict[str, str]:
    prefix, _, rest = vector.partition("/")
    if prefix != "CVSS:3.1":
        raise ValueError("vector must start with CVSS:3.1/")
    metrics = dict(part.split(":", 1) for part in rest.split("/") if ":" in part)
    if tuple(metrics) != ORDER or len(rest.split("/")) != len(ORDER):
        raise ValueError(f"vector must contain exactly {'/'.join(ORDER)} in order")
    if metrics["S"] not in ("U", "C") or metrics["PR"] not in PRIVILEGES["U"]:
        raise ValueError("invalid S or PR value")
    for name, table in WEIGHTS.items():
        if metrics[name] not in table:
            raise ValueError(f"invalid value for {name}: {metrics[name]}")
    return metrics


def score(vector: str) -> Score:
    m = parse(vector)
    changed = m["S"] == "C"
    iss = 1 - (1 - WEIGHTS["C"][m["C"]]) * (1 - WEIGHTS["I"][m["I"]]) * (1 - WEIGHTS["A"][m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploitability = (8.22 * WEIGHTS["AV"][m["AV"]] * WEIGHTS["AC"][m["AC"]]
                      * PRIVILEGES[m["S"]][m["PR"]] * WEIGHTS["UI"][m["UI"]])
    if impact <= 0:
        base = 0.0
    elif changed:
        base = roundup(min(1.08 * (impact + exploitability), 10))
    else:
        base = roundup(min(impact + exploitability, 10))
    return Score(vector=vector, iss=iss, impact=impact, exploitability=exploitability, base=base)


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        result = score(arg)
        print(f"{result.base:.1f} {result.severity:<8} impact={result.impact:.2f} "
              f"exploitability={result.exploitability:.2f}  {arg}")
