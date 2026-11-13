"""Replay labelled traffic against a localhost fixture and score the Sigma rules.

For each fixture variant the runner starts the app on 127.0.0.1:5000 with the
opt-in audit log enabled, sends every request in ``traffic.jsonl``, reads the
audit events back, applies the stateful enrichment and evaluates every rule
against every event. An attack request must raise exactly the rule for its
finding; a benign request must raise nothing. Any mismatch fails the run.

Only loopback is contacted. The corpus contains no third-party hosts and no real
cloud-metadata addresses; those patterns are covered offline in ``tests/``.

    python -m detections.validate --output detection-report.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

from detections.engine import load_rules
from detections.enrich import enrich

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
BASE_URL = "http://127.0.0.1:5000"
REQUEST_ID_HEADER = "X-Lab-Request-Id"
VARIANTS = {
    "vulnerable": (ROOT / "vulnerable-app" / "app.py", "vulnerable by design"),
    "patched": (ROOT / "remediation" / "patched_app.py", "(patched)"),
}


def load_corpus(path: Path) -> list[dict]:
    entries = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    ids = [entry["id"] for entry in entries]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate corpus ids")
    for entry in entries:
        if entry["label"] not in ("attack", "benign"):
            raise ValueError(f"{entry['id']}: bad label")
        if (entry["label"] == "attack") != ("finding" in entry):
            raise ValueError(f"{entry['id']}: attack entries, and only those, need a finding")
    return entries


def _port_in_use() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", 5000)) == 0


def _wait_ready(proc: subprocess.Popen, marker: str) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"fixture exited early with status {proc.returncode}")
        try:
            response = requests.get(BASE_URL + "/", timeout=0.5)
            if response.status_code == 200 and marker in response.text:
                return
            raise RuntimeError("an unexpected application answered on 127.0.0.1:5000")
        except requests.ConnectionError:
            time.sleep(0.15)
    raise RuntimeError("fixture did not become ready within 20 seconds")


def replay(corpus: list[dict], variant: str) -> list[dict]:
    """Send the corpus to one fixture variant; return its audit events in order."""
    app_path, marker = VARIANTS[variant]
    if _port_in_use():
        raise RuntimeError("refusing to reuse port 5000: a process is already listening")
    with tempfile.TemporaryDirectory() as tmp:
        audit_path = Path(tmp) / "audit.jsonl"
        env = dict(os.environ, LAB_AUDIT_LOG=str(audit_path))
        proc = subprocess.Popen([sys.executable, "-u", str(app_path)], cwd=str(ROOT), env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            _wait_ready(proc, marker)
            tokens: dict[str, str] = {}
            for entry in corpus:
                headers = {REQUEST_ID_HEADER: entry["id"]}
                for name, value in entry.get("headers", {}).items():
                    if value.startswith("{{token:") and value.endswith("}}"):
                        value = tokens[value[len("{{token:"):-2]]
                    headers[name] = value
                response = requests.request(entry["method"], BASE_URL + entry["path"],
                                            params=entry.get("params"), json=entry.get("json"),
                                            headers=headers, timeout=10)
                if "capture_token" in entry:
                    tokens[entry["capture_token"]] = response.json()["token"]
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        lines = audit_path.read_text(encoding="utf-8").splitlines() if audit_path.exists() else []
    return [json.loads(line) for line in lines]


def score(corpus: list[dict], events: list[dict], rules) -> dict:
    by_request = {event["lab_request_id"]: event for event in enrich(events) if "lab_request_id" in event}
    rule_for_finding = {rule.finding: rule for rule in rules}
    per_rule = {rule.rule_id: {"finding": rule.finding, "title": rule.title, "attack_events": 0,
                               "detected": 0, "missed": [], "false_alerts": []} for rule in rules}
    rows, mismatches = [], []
    for entry in corpus:
        event = by_request.get(entry["id"])
        if event is None:
            mismatches.append(f"{entry['id']}: no audit event recorded")
            continue
        fired = sorted(rule.rule_id for rule in rules if rule.matches(event))
        expected = [rule_for_finding[entry["finding"]].rule_id] if entry["label"] == "attack" else []
        if entry["label"] == "attack":
            stats = per_rule[expected[0]]
            stats["attack_events"] += 1
            if expected[0] in fired:
                stats["detected"] += 1
            else:
                stats["missed"].append(entry["id"])
        for rule_id in fired:
            if rule_id not in expected:
                per_rule[rule_id]["false_alerts"].append(entry["id"])
        if fired != expected:
            mismatches.append(f"{entry['id']}: expected {expected or 'no alert'}, got {fired or 'no alert'}")
        rows.append({"id": entry["id"], "label": entry["label"], "finding": entry.get("finding"),
                     "status": event["sc-status"], "alerts": fired, "note": entry.get("note", "")})

    attacks = sum(1 for entry in corpus if entry["label"] == "attack")
    benign = len(corpus) - attacks
    detected = sum(stats["detected"] for stats in per_rule.values())
    false_alert_events = len({eid for stats in per_rule.values() for eid in stats["false_alerts"]})
    alerts_total = detected + sum(len(stats["false_alerts"]) for stats in per_rule.values())
    return {
        "attack_events": attacks,
        "benign_events": benign,
        "attack_events_detected": detected,
        "recall": round(detected / attacks, 4) if attacks else None,
        "benign_or_misattributed_events_alerted": false_alert_events,
        "precision": round(detected / alerts_total, 4) if alerts_total else None,
        "per_rule": per_rule,
        "events": rows,
        "mismatches": mismatches,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, help="write the JSON report to this path")
    parser.add_argument("--variant", choices=[*VARIANTS, "both"], default="both")
    args = parser.parse_args(argv)

    corpus_path = HERE / "traffic.jsonl"
    corpus = load_corpus(corpus_path)
    rules = load_rules(HERE / "rules")
    findings = sorted(rule.finding for rule in rules)
    needed = sorted({entry["finding"] for entry in corpus if entry["label"] == "attack"})
    if findings != needed:
        raise SystemExit(f"rules cover findings {findings} but the corpus attacks {needed}")

    report = {
        "provenance": "labelled synthetic traffic replayed against this repository's own localhost fixtures",
        "not_claimed": "production detection efficacy, coverage of unseen payloads, or third-party validation",
        "corpus_sha256": hashlib.sha256(corpus_path.read_bytes()).hexdigest(),
        "rules": [{"id": rule.rule_id, "finding": rule.finding, "file": rule.path.name} for rule in rules],
        "variants": {},
    }
    failed = False
    for variant in (VARIANTS if args.variant == "both" else [args.variant]):
        result = score(corpus, replay(corpus, variant), rules)
        report["variants"][variant] = result
        print(f"[{variant}] attacks detected {result['attack_events_detected']}/{result['attack_events']} "
              f"(recall {result['recall']}), benign or misattributed events alerted "
              f"{result['benign_or_misattributed_events_alerted']}/{result['benign_events']} "
              f"(precision {result['precision']})")
        for line in result["mismatches"]:
            print(f"  MISMATCH {line}", file=sys.stderr)
        failed = failed or bool(result["mismatches"])

    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
