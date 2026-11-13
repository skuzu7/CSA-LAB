"""Opt-in structured audit log shared by both localhost fixtures.

Disabled unless the LAB_AUDIT_LOG environment variable names a file. When enabled,
every HTTP request appends one JSON object using the W3C/Sigma web-server field
names (cs-method, cs-uri-stem, cs-uri-query, sc-status) plus the application-audit
fields a handler chose to record with ``note()``.

The log exists so detections in ``detections/`` can be validated against real
requests. It never leaves the local filesystem and holds synthetic data only.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone

from flask import g, request

REQUEST_ID_HEADER = "X-Lab-Request-Id"
_LOCK = threading.Lock()


def note(**fields) -> None:
    """Attach application-level audit fields to the current request's event."""
    audit = getattr(g, "lab_audit", None)
    if audit is None:
        audit = g.lab_audit = {}
    audit.update(fields)


def install(app) -> bool:
    """Register the audit hook on ``app``. Returns False when logging is off."""
    path = os.environ.get("LAB_AUDIT_LOG")
    if not path:
        return False

    @app.after_request
    def _write_audit_event(response):
        event = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "c-ip": request.remote_addr,
            "cs-method": request.method,
            "cs-uri-stem": request.path,
            "cs-uri-query": request.query_string.decode("latin-1"),
            "sc-status": response.status_code,
        }
        request_id = request.headers.get(REQUEST_ID_HEADER)
        if request_id:
            event["lab_request_id"] = request_id[:64]
        event.update(getattr(g, "lab_audit", {}))
        line = json.dumps(event, sort_keys=True)
        with _LOCK, open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        return response

    return True
