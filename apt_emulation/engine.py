"""Offline, synthetic ATT&CK sequence correlation. No network or attack execution."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from pathlib import Path
import json
from typing import Any

STAGES: tuple[tuple[str, str, str], ...] = (
    ("initial_access", "T1190", "web_access_anomaly"),
    ("discovery", "T1082", "system_inventory_observed"),
    ("persistence", "T1547.001", "autorun_configuration_observed"),
    ("lateral_movement", "T1021.002", "share_session_observed"),
    ("collection", "T1005", "fixture_file_access_observed"),
    ("command_and_control", "T1071.001", "periodic_web_traffic_observed"),
    ("exfiltration", "T1041", "outbound_bytes_observed"),
)

def parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO 8601 string")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid ISO 8601 timestamp") from exc
    if result.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return result

def validate_cases(cases: list[dict[str, Any]]) -> None:
    if not isinstance(cases, list) or not cases:
        raise ValueError("nonempty cases array required")
    seen: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str):
            raise ValueError("each case requires a string id")
        if case["id"] in seen:
            raise ValueError("duplicate case id")
        seen.add(case["id"])
        if type(case.get("expected_alert")) is not bool:
            raise ValueError("expected_alert must be boolean")
        if not isinstance(case.get("events"), list):
            raise ValueError("events must be a list")
        for event in case["events"]:
            if not isinstance(event, dict) or event.get("synthetic") is not True:
                raise ValueError("all events must be explicitly synthetic")
            for field in ("timestamp", "actor", "campaign", "host", "technique", "event_type"):
                if not isinstance(event.get(field), str) or not event[field]:
                    raise ValueError(f"missing or invalid {field}")
            parse_time(event["timestamp"])

def load_cases(path: Path | None = None) -> list[dict[str, Any]]:
    source = path or Path(__file__).with_name("fixtures.json")
    cases = json.loads(source.read_text(encoding="utf-8"))
    validate_cases(cases)
    return cases

def detect_case(case: dict[str, Any], window_seconds: int = 1800) -> dict[str, Any]:
    """Correlate a synthetic seven-signal sequence per actor and campaign."""
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    validate_cases([case])
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in case["events"]:
        grouped[(event["actor"], event["campaign"])].append(event)
    for (actor, campaign), events in grouped.items():
        events.sort(key=lambda item: parse_time(item["timestamp"]))
        for start_index, first in enumerate(events):
            if (first["technique"], first["event_type"]) != STAGES[0][1:]:
                continue
            matched = [first]
            started = parse_time(first["timestamp"])
            next_stage = 1
            for event in events[start_index + 1:]:
                when = parse_time(event["timestamp"])
                if (when - started).total_seconds() > window_seconds:
                    break
                if (event["technique"], event["event_type"]) == STAGES[next_stage][1:]:
                    matched.append(event)
                    next_stage += 1
                    if next_stage == len(STAGES):
                        return {
                            "alert": True, "actor": actor, "campaign": campaign,
                            "techniques": [item["technique"] for item in matched],
                            "matched_timestamps": [item["timestamp"] for item in matched],
                            "duration_seconds": int((when - started).total_seconds()),
                        }
    return {
        "alert": False, "actor": None, "campaign": None,
        "techniques": [], "matched_timestamps": [], "duration_seconds": None,
    }

def evaluate(cases: list[dict[str, Any]]) -> dict[str, Any]:
    validate_cases(cases)
    rows = []
    confusion = {
        "true_positive": 0, "true_negative": 0, "false_positive": 0, "false_negative": 0,
    }
    for case in cases:
        result = detect_case(case)
        expected = case["expected_alert"]
        key = ("true_positive" if expected else "false_positive") if result["alert"] else (
            "false_negative" if expected else "true_negative"
        )
        confusion[key] += 1
        rows.append({
            "id": case["id"], "expected_alert": expected, **result,
            "correct": result["alert"] == expected,
        })
    return {
        "scope": "Synthetic offline events. Not a real APT intrusion or production accuracy estimate.",
        "attack_mapping": [
            {"stage": stage, "technique": technique, "event_type": event_type}
            for stage, technique, event_type in STAGES
        ],
        "cases": rows,
        "confusion_matrix": confusion,
        "all_expected_outcomes_met": all(row["correct"] for row in rows),
    }
