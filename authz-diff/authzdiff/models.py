from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class RequestSpec:
    """One captured request, as the owner sent it."""

    method: str
    url: str
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes | None = None

    @property
    def path(self) -> str:
        parts = urlsplit(self.url)
        return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


@dataclass(frozen=True)
class Response:
    """What came back. `status` is 0 when the request failed before a status line."""

    status: int
    body: bytes = b""
    content_type: str = ""
    location: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300
