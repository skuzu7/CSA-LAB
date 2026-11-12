"""Host-side mock tool authorization. It NEVER executes the proposed operation.

Educational policy example: not a production sandbox, network filter, or file API.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

SENSITIVE = frozenset({".env", ".env.local", ".env.production", "id_rsa", "id_ed25519", ".ssh", ".git", "secrets.json", "credentials.json"})


@dataclass(frozen=True)
class ToolCall:
    operation: str
    target: str

    def key(self) -> tuple[str, str]:
        return self.operation, self.target


@dataclass(frozen=True)
class TrustedContext:
    workspace: Path
    planned_actions: frozenset[tuple[str, str]]
    approved_writes: frozenset[tuple[str, str]] = frozenset()
    allowed_hosts: frozenset[str] = frozenset({"kb.example.test"})


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def _check_path(target: str, root: Path) -> Decision:
    if not target or "\x00" in target or "\\" in target:
        return Decision(False, "malformed-path")
    raw = Path(target)
    if raw.is_absolute() or ".." in raw.parts:
        return Decision(False, "traversal-or-absolute-path")
    if any(part.lower() in SENSITIVE or part.lower().startswith(".env.") for part in raw.parts):
        return Decision(False, "sensitive-path")
    workspace = root.resolve()
    resolved = (workspace / raw).resolve(strict=False)
    if not resolved.is_relative_to(workspace):
        return Decision(False, "out-of-workspace")
    return Decision(True, "scoped-path")


def _check_url(target: str, allowlist: frozenset[str]) -> Decision:
    try:
        parts = urlsplit(target)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        return Decision(False, "invalid-url")
    if parts.scheme != "https" or not hostname or parts.username or parts.password:
        return Decision(False, "invalid-https-authority")
    if parts.fragment or port not in (None, 443) or hostname not in allowlist:
        return Decision(False, "url-out-of-scope")
    try:
        ip = ipaddress.ip_address(hostname)
        if not ip.is_global:
            return Decision(False, "nonpublic-ip")
    except ValueError:
        pass  # DNS/redirect/IP enforcement is explicitly OUTSIDE this example.
    return Decision(True, "syntactic-allowlisted-url")


def authorize(call: ToolCall, trusted: TrustedContext) -> Decision:
    if call.operation not in {"read_file", "write_file", "http_get"}:
        return Decision(False, "unsupported-operation")
    if call.operation in {"read_file", "write_file"}:
        checked = _check_path(call.target, trusted.workspace)
    else:
        checked = _check_url(call.target, trusted.allowed_hosts)
    if not checked.allowed:
        return checked
    if call.key() not in trusted.planned_actions:
        return Decision(False, "not-in-trusted-task-plan")
    if call.operation == "write_file" and call.key() not in trusted.approved_writes:
        return Decision(False, "write-not-approved")
    return Decision(True, "authorized-by-trusted-host")
