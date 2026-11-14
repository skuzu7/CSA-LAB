"""Send a captured request as a given identity."""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from http.client import HTTPException

from . import __version__
from .config import Config, Identity
from .models import RequestSpec, Response
from .scope import in_scope

MAX_BODY = 2 * 1024 * 1024

# Headers the HTTP client must compute itself, or that would turn a replay
# into a cache revalidation (304) instead of a real answer.
_DROP = frozenset(
    {
        "host", "content-length", "accept-encoding", "connection", "proxy-connection",
        "transfer-encoding", "te", "upgrade", "if-none-match", "if-modified-since",
    }
)


class OutOfScope(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: a 3xx is itself the answer, and the target may be out of scope."""

    def redirect_request(self, *args, **kwargs):
        return None


class RateLimiter:
    def __init__(self, per_second: float) -> None:
        self._interval = 1.0 / per_second
        self._next = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        if now < self._next:
            time.sleep(self._next - now)
            now = self._next
        self._next = now + self._interval


def build_headers(spec: RequestSpec, identity: Identity | None, cfg: Config) -> list[tuple[str, str]]:
    """Captured headers minus every credential, plus the identity's own (none for anonymous)."""
    merged: dict[str, tuple[str, str]] = {}
    for name, value in spec.headers:
        key = name.lower()
        if key.startswith(":") or key in _DROP or key in cfg.auth_headers:
            continue
        merged[key] = (name, value)
    for name, value in cfg.extra_headers.items():
        merged[name.lower()] = (name, value)
    if identity is not None:
        for name, value in identity.headers.items():
            merged[name.lower()] = (name, value)
    merged.setdefault("user-agent", ("User-Agent", f"authzdiff/{__version__}"))
    return list(merged.values())


class Client:
    def __init__(self, cfg: Config, proxy: str | None = None, cafile: str | None = None) -> None:
        self._cfg = cfg
        self._limiter = RateLimiter(cfg.rate_limit)
        context = ssl.create_default_context()
        if cafile:
            context.load_verify_locations(cafile=cafile)  # in addition to the system CAs
        handlers: list = [_NoRedirect(), urllib.request.HTTPSHandler(context=context)]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        self._opener = urllib.request.build_opener(*handlers)
        self.sent = 0

    def send(self, spec: RequestSpec, identity: Identity | None) -> Response:
        # Selection already filtered by scope; this check is the last line of
        # defence if a caller hands the client something else.
        if not in_scope(spec.url, self._cfg.scope_hosts):
            raise OutOfScope(spec.url)
        request = urllib.request.Request(spec.url, data=spec.body, method=spec.method)
        for name, value in build_headers(spec, identity, self._cfg):
            request.add_header(name, value)
        self._limiter.wait()
        self.sent += 1
        try:
            with self._opener.open(request, timeout=self._cfg.timeout) as reply:
                return _response(reply.status, reply.headers, reply.read(MAX_BODY))
        except urllib.error.HTTPError as exc:
            return _response(exc.code, exc.headers, exc.read(MAX_BODY))
        except (urllib.error.URLError, HTTPException, OSError, ValueError) as exc:
            return Response(status=0, error=str(getattr(exc, "reason", exc)))


def _response(status: int, headers, body: bytes) -> Response:
    return Response(
        status=status,
        body=body,
        content_type=headers.get("Content-Type", "") or "",
        location=headers.get("Location", "") or "",
    )
