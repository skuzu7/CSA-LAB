"""PolicyForge: offline, fail-closed policy evaluation for simulated agent tool calls.

No tool is ever executed. This module evaluates synthetic plans against a
trusted policy. It is a research prototype, not an MCP server or a sandbox.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

DANGEROUS_ACTIONS = frozenset({"delete", "execute", "publish", "secrets.read", "git.force_push"})
ALLOWED_SOURCES = frozenset({"direct_user", "tool_output", "retrieval"})
ZERO_HASH = "0" * 64


@dataclass(frozen=True)
class Decision:
    id: str
    allowed: bool
    reason: str
    audit_sha256: str


def safe_resource(value: object, *, prefix: bool = False) -> bool:
    """Accept canonical repo://owner/repo/path only (no external URLs or traversal)."""
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        return False
    if any(x in value for x in ("%", "\\", "\x00", "\r", "\n")):
        return False
    try:
        target = urlsplit(value)
    except ValueError:
        return False
    if target.scheme != "repo" or not re.fullmatch(r"[a-zA-Z0-9_.-]+", target.netloc or ""):
        return False
    if target.query or target.fragment or not target.path.startswith("/"):
        return False
    path = target.path[1:]
    if prefix and path.endswith("/"):
        path = path[:-1]
    segments = path.split("/")
    return bool(segments) and all(
        segment not in ("", ".", "..") and re.fullmatch(r"[a-zA-Z0-9_.-]+", segment)
        for segment in segments
    )


def resource_in_scope(resource: str, grant_prefix: str) -> bool:
    if not safe_resource(resource) or not safe_resource(grant_prefix, prefix=True):
        return False
    return (
        resource.startswith(grant_prefix)
        if grant_prefix.endswith("/")
        else resource == grant_prefix or resource.startswith(grant_prefix + "/")
    )


class Gate:
    """One trusted evaluator instance. Approvals are consumed only once."""

    def __init__(self, policy: dict):
        if not isinstance(policy, dict):
            raise TypeError("Policy must be a trusted mapping")
        self.grants = policy.get("grants", [])
        self.approvals = policy.get("approvals", {})
        if not isinstance(self.grants, list) or not isinstance(self.approvals, dict):
            raise TypeError("Invalid policy schema")
        self.used_approvals: set[str] = set()
        self.audit_head = ZERO_HASH

    def _decide(self, call: dict, seen: dict[str, bool]) -> str:
        required = ("id", "actor", "tool", "action", "resource", "source")
        if any(not isinstance(call.get(key), str) or not call[key] for key in required):
            return "invalid_request"
        if call["source"] not in ALLOWED_SOURCES:
            return "invalid_request"
        if call["id"] in seen:
            return "duplicate_step"
        deps = call.get("depends_on", [])
        if not isinstance(deps, list) or any(not isinstance(d, str) or not seen.get(d) for d in deps):
            return "dependency_denied"
        if not safe_resource(call["resource"]):
            return "unsafe_resource"

        authorized = False
        for grant in self.grants:
            if not isinstance(grant, dict):
                continue
            if (
                call["actor"] == grant.get("actor")
                and call["tool"] == grant.get("tool")
                and call["action"] == grant.get("action")
                and isinstance(grant.get("resource"), str)
                and resource_in_scope(call["resource"], grant["resource"])
            ):
                authorized = True
                break
        if not authorized:
            return "no_grant"

        if call["action"] in DANGEROUS_ACTIONS:
            approval_id = call.get("approval_id")
            approval = self.approvals.get(approval_id) if isinstance(approval_id, str) else None
            if not isinstance(approval, dict) or approval_id in self.used_approvals:
                return "approval_required"
            for field in ("actor", "tool", "action", "resource"):
                if approval.get(field) != call[field]:
                    return "approval_required"
            self.used_approvals.add(approval_id)
        return "allow"

    def evaluate(self, steps: list[dict]) -> list[Decision]:
        if not isinstance(steps, list):
            raise TypeError("Plan must be a list")
        seen: dict[str, bool] = {}
        results: list[Decision] = []
        for index, call in enumerate(steps):
            step = call if isinstance(call, dict) else {}
            reason = self._decide(step, seen)
            allowed = reason == "allow"
            step_id = step.get("id") if isinstance(step.get("id"), str) else ""
            record = {
                "index": index,
                "step": step,
                "allowed": allowed,
                "reason": reason,
                "previous": self.audit_head,
            }
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            self.audit_head = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            results.append(Decision(step_id, allowed, reason, self.audit_head))
            if step_id not in seen:
                seen[step_id] = allowed
        return results
