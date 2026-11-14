"""Read requests out of a HAR file (browser devtools, Burp, mitmproxy, ZAP)."""

from __future__ import annotations

import base64
import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from .config import Config
from .models import RequestSpec
from .scope import in_scope

STATIC_EXTENSIONS = frozenset(
    {
        ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".webp", ".avif", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".mp3",
    }
)


class HarError(ValueError):
    pass


def load_har(path: str | Path) -> list[RequestSpec]:
    try:
        entries = json.loads(Path(path).read_text(encoding="utf-8-sig"))["log"]["entries"]
    except OSError as exc:
        raise HarError(f"cannot read HAR: {exc}") from exc
    except (ValueError, KeyError, TypeError) as exc:
        raise HarError(f"{path} is not a HAR file (no log.entries)") from exc

    specs = []
    for entry in entries:
        request = entry.get("request") or {}
        if not request.get("url") or not request.get("method"):
            continue
        post = request.get("postData") or {}
        body = None
        if post.get("text"):
            raw = post["text"]
            body = base64.b64decode(raw) if post.get("encoding") == "base64" else raw.encode()
        specs.append(
            RequestSpec(
                method=request["method"].upper(),
                url=request["url"],
                headers=tuple((h["name"], h.get("value", "")) for h in request.get("headers", []) if h.get("name")),
                body=body,
            )
        )
    return specs


def is_static(url: str) -> bool:
    path = urlsplit(url).path.lower()
    dot = path.rfind(".")
    return dot > path.rfind("/") and path[dot:] in STATIC_EXTENSIONS


def select(specs: list[RequestSpec], cfg: Config) -> tuple[list[RequestSpec], Counter]:
    """Keep the requests worth replaying; count what was dropped and why."""
    chosen: list[RequestSpec] = []
    dropped: Counter = Counter()
    seen = set()
    for spec in specs:
        if not in_scope(spec.url, cfg.scope_hosts):
            dropped["out of scope"] += 1
        elif spec.method not in cfg.methods:
            dropped["method not enabled"] += 1
        elif is_static(spec.url):
            dropped["static asset"] += 1
        elif (key := (spec.method, spec.url, spec.body)) in seen:
            dropped["duplicate"] += 1
        else:
            seen.add(key)
            chosen.append(spec)
    return chosen, dropped
