"""Scope enforcement: nothing is sent to a host the config does not list."""

from __future__ import annotations

from fnmatch import fnmatchcase
from urllib.parse import urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _split_pattern(pattern: str) -> tuple[str, str]:
    """Split `host`, `host:port` or `[v6]:port` into (host, port). Port may be '' or '*'."""
    pattern = pattern.strip().lower()
    if pattern.startswith("["):
        host, _, rest = pattern[1:].partition("]")
        return host, rest.lstrip(":")
    host, sep, port = pattern.rpartition(":")
    if sep and (port.isdigit() or port == "*"):
        return host, port
    return pattern, ""


def in_scope(url: str, patterns: tuple[str, ...]) -> bool:
    """True when the URL's host and port match one of the scope patterns.

    A pattern without a port only matches the scheme's default port, so an
    in-scope hostname does not silently cover other services on that host.
    Use `host:8443` for one port or `host:*` for any.
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    if parts.scheme not in _DEFAULT_PORTS or not parts.hostname:
        return False
    host = parts.hostname.lower()
    port = port or _DEFAULT_PORTS[parts.scheme]
    for pattern in patterns:
        want_host, want_port = _split_pattern(pattern)
        if not fnmatchcase(host, want_host):
            continue
        if want_port == "*":
            return True
        if int(want_port or _DEFAULT_PORTS[parts.scheme]) == port:
            return True
    return False
