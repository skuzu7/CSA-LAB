"""Pytest fixtures: boot the app (vulnerable or patched) on 127.0.0.1:5000.

LAB_APP_VARIANT=vulnerable|patched (default vulnerable).
"""
import os
import subprocess
import sys
import time

import pytest
import requests

BASE = "http://127.0.0.1:5000"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _wait_ready(timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if requests.get(BASE + "/", timeout=1).status_code == 200:
                return True
        except Exception:
            time.sleep(0.3)
    raise RuntimeError("lab app did not start")


@pytest.fixture(scope="session", autouse=True)
def lab_app():
    variant = os.environ.get("LAB_APP_VARIANT", "vulnerable")
    entry = "app.py" if variant == "vulnerable" else os.path.join("..", "remediation", "patched_app.py")
    workdir = os.path.join(ROOT, "vulnerable-app")
    proc = subprocess.Popen([sys.executable, entry], cwd=workdir,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_ready()
        os.environ["LAB_BASE_URL"] = BASE
        yield {"variant": variant, "base": BASE}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
