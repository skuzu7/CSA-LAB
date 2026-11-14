from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .models import RequestSpec

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

DEFAULT_AUTH_HEADERS = frozenset(
    {"authorization", "cookie", "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token"}
)
DEFAULT_IGNORE_KEYS = frozenset(
    {
        "timestamp", "time", "date", "server_time", "generated_at", "request_id",
        "requestid", "trace_id", "traceid", "nonce", "csrf", "csrf_token",
    }
)

_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Identity:
    name: str
    headers: dict[str, str]
    markers: tuple[str, ...]


@dataclass(frozen=True)
class Config:
    scope_hosts: tuple[str, ...]
    owner: Identity
    other: Identity
    methods: frozenset[str]
    rate_limit: float
    timeout: float
    auth_headers: frozenset[str]
    extra_headers: dict[str, str]
    similarity_threshold: float
    ignore_keys: frozenset[str]
    requests: tuple[RequestSpec, ...]


def _expand(value: str, where: str) -> str:
    """Replace ${VAR} with the environment value so secrets stay out of files."""

    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in os.environ:
            raise ConfigError(f"{where}: environment variable {name} is not set")
        return os.environ[name]

    return _ENV.sub(repl, value)


def _identity(raw: dict, key: str) -> Identity:
    data = raw.get("identities", {}).get(key)
    if not isinstance(data, dict):
        raise ConfigError(f"missing [identities.{key}]")
    headers = data.get("headers")
    if not isinstance(headers, dict) or not headers:
        raise ConfigError(f"[identities.{key}] needs a non-empty `headers` table")
    markers = data.get("markers", [])
    if not isinstance(markers, list) or not all(isinstance(m, str) and m for m in markers):
        raise ConfigError(f"[identities.{key}] `markers` must be a list of non-empty strings")
    return Identity(
        name=str(data.get("name", key)),
        headers={str(k): _expand(str(v), f"identities.{key}.headers.{k}") for k, v in headers.items()},
        markers=tuple(markers),
    )


def _inline_requests(raw: dict) -> tuple[RequestSpec, ...]:
    specs = []
    for i, item in enumerate(raw.get("requests", [])):
        if not isinstance(item, dict) or "url" not in item:
            raise ConfigError(f"[[requests]] entry {i + 1} needs a `url`")
        body = item.get("body")
        specs.append(
            RequestSpec(
                method=str(item.get("method", "GET")).upper(),
                url=str(item["url"]),
                headers=tuple((str(k), str(v)) for k, v in item.get("headers", {}).items()),
                body=body.encode() if isinstance(body, str) else None,
            )
        )
    return tuple(specs)


def load_config(path: str | Path) -> Config:
    try:
        raw = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from exc

    hosts = raw.get("scope", {}).get("hosts")
    if not isinstance(hosts, list) or not hosts or not all(isinstance(h, str) and h for h in hosts):
        raise ConfigError("[scope] `hosts` must list the hosts you are authorized to test")

    owner, other = _identity(raw, "owner"), _identity(raw, "other")
    settings = raw.get("settings", {})

    rate_limit = float(settings.get("rate_limit", 2.0))
    threshold = float(settings.get("similarity_threshold", 0.95))
    if rate_limit <= 0:
        raise ConfigError("settings.rate_limit must be greater than 0")
    if not 0 < threshold <= 1:
        raise ConfigError("settings.similarity_threshold must be in (0, 1]")

    # Any header an identity sets is a credential: strip it from the captured
    # request before replaying as someone else.
    auth_headers = (
        DEFAULT_AUTH_HEADERS
        | {h.lower() for h in settings.get("auth_headers", [])}
        | {h.lower() for h in owner.headers}
        | {h.lower() for h in other.headers}
    )

    return Config(
        scope_hosts=tuple(hosts),
        owner=owner,
        other=other,
        methods=frozenset(m.upper() for m in settings.get("methods", ["GET"])),
        rate_limit=rate_limit,
        timeout=float(settings.get("timeout", 15.0)),
        auth_headers=frozenset(auth_headers),
        extra_headers={str(k): str(v) for k, v in settings.get("extra_headers", {}).items()},
        similarity_threshold=threshold,
        ignore_keys=DEFAULT_IGNORE_KEYS | {k.lower() for k in settings.get("ignore_keys", [])},
        requests=_inline_requests(raw),
    )
