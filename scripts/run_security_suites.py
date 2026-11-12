"""Run both CSA-LAB test suites against their own localhost-only app variant.

No external targets are accepted. The runner starts and stops a fresh local
Flask fixture per suite, ensuring CI and local reproduction use the same path.
"""
from __future__ import annotations

import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "http://127.0.0.1:5000"
CASES = (
    ("vulnerable", ROOT / "vulnerable-app" / "app.py", "tests/security", "vulnerable by design"),
    ("patched", ROOT / "remediation" / "patched_app.py", "tests/regression", "(patched)"),
)


def ensure_port_available() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        if sock.connect_ex(("127.0.0.1", 5000)) == 0:
            raise RuntimeError("Refusing to reuse port 5000: a process is already listening.")


def wait_ready(proc: subprocess.Popen, variant_marker: str) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"Fixture exited before becoming ready (status {proc.returncode}).")
        try:
            with urllib.request.urlopen(BASE_URL + "/", timeout=0.5) as resp:
                body = resp.read(2048).decode("utf-8", errors="replace")
                if resp.status == 200 and variant_marker in body:
                    return
                raise RuntimeError("Unexpected app responded on localhost:5000.")
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            time.sleep(0.15)
    raise RuntimeError("Fixture did not become ready within 20 seconds.")


def run_suite(name: str, app_path: Path, test_dir: str, marker: str) -> bool:
    ensure_port_available()
    print(f"\n=== {name} fixture: {test_dir} ===", flush=True)
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as server_log:
        proc = subprocess.Popen(
            [sys.executable, "-u", str(app_path)],
            cwd=str(ROOT),
            stdout=server_log,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_ready(proc, marker)
            env = dict(os.environ, LAB_BASE_URL=BASE_URL)
            completed = subprocess.run(
                [sys.executable, "-m", "pytest", test_dir, "-v"],
                cwd=str(ROOT),
                env=env,
                check=False,
            )
            if completed.returncode != 0:
                print(f"{name} test suite failed with code {completed.returncode}.", file=sys.stderr)
            return completed.returncode == 0
        except Exception as exc:
            print(f"Unable to run {name}: {exc}", file=sys.stderr)
            return False
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
            server_log.seek(0)
            logs = server_log.read()
            if logs and proc.returncode not in (-15, 0):
                print(f"[{name} server output]\n{logs[-4000:]}", file=sys.stderr)


def main() -> int:
    for name, path, suite, marker in CASES:
        if not run_suite(name, path, suite, marker):
            return 1
    print("\nBoth localhost-only suites passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
