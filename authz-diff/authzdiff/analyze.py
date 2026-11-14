"""Decide what three responses to the same request say about access control."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from enum import Enum
from urllib.parse import parse_qsl, urlsplit

from .config import Config
from .models import RequestSpec, Response

_COMPARE_CAP = 10_000
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


class Verdict(str, Enum):
    VULNERABLE = "VULNERABLE"  # someone else received the owner's marked data
    SUSPECT = "SUSPECT"        # same answer for two users behind auth: review by hand
    PUBLIC = "PUBLIC"          # same answer with no credentials, no owner data seen
    DIFFERS = "DIFFERS"        # other user got a 2xx with different content
    ENFORCED = "ENFORCED"      # other user was refused
    SKIPPED = "SKIPPED"        # the owner's own request did not succeed


SEVERITY = [Verdict.VULNERABLE, Verdict.SUSPECT, Verdict.PUBLIC, Verdict.DIFFERS, Verdict.ENFORCED, Verdict.SKIPPED]


@dataclass(frozen=True)
class Result:
    request: RequestSpec
    verdict: Verdict
    reason: str
    owner: Response
    other: Response | None = None
    anon: Response | None = None
    similarity_other: float | None = None
    similarity_anon: float | None = None
    leaked_markers: tuple[str, ...] = ()
    leaked_to: str = ""  # "other" or "anonymous"


@dataclass(frozen=True)
class Content:
    """A response body in comparable form."""

    text: str                 # what markers are searched in
    leaves: frozenset | None  # (path, value) pairs when the body is JSON


def _leaves(data, ignore: frozenset[str], path: tuple = ()):
    if isinstance(data, dict):
        items = [(k, v) for k, v in data.items() if k.lower() not in ignore]
    elif isinstance(data, list):
        items = list(enumerate(data))
    else:
        yield path, data
        return
    if not items:
        yield path, "{}" if isinstance(data, dict) else "[]"
    for key, value in items:
        yield from _leaves(value, ignore, path + (key,))


def content(body: bytes, ignore: frozenset[str]) -> Content:
    """Parse JSON into its leaf values, minus volatile keys; keep anything else as text."""
    text = body.decode("utf-8", "replace")
    try:
        data = json.loads(text)
    except ValueError:
        return Content(text, None)
    leaves = frozenset(_leaves(data, ignore))
    # Search markers in decoded values, so "Jos\u00e9" in the raw body still matches "José".
    return Content("\n".join(str(value) for _, value in leaves), leaves)


def similarity(a: Content, b: Content) -> float:
    """1.0 for the same content. JSON is compared value by value, so two users'
    records with the same shape but different data score low."""
    if a.leaves is not None and b.leaves is not None:
        if a.leaves == b.leaves:
            return 1.0
        return len(a.leaves & b.leaves) / len(a.leaves | b.leaves)
    if a.text == b.text:
        return 1.0
    matcher = SequenceMatcher(None, a.text[:_COMPARE_CAP], b.text[:_COMPARE_CAP], autojunk=False)
    # quick_ratio is a cheap upper bound; skip the quadratic pass when it is already low.
    quick = matcher.quick_ratio()
    return quick if quick < 0.5 else matcher.ratio()


def has_object_reference(url: str) -> bool:
    """True when the URL names a specific object: a numeric or UUID path segment, or an *id parameter."""
    parts = urlsplit(url)
    if any(seg.isdigit() or _UUID.match(seg) for seg in parts.path.split("/") if seg):
        return True
    return any(key.lower().endswith("id") and value for key, value in parse_qsl(parts.query))


def baseline_failed(spec: RequestSpec, owner: Response) -> Result:
    """Without a successful answer for the owner there is nothing to compare against."""
    if 300 <= owner.status < 400:
        reason = f"owner was redirected ({owner.status} to {owner.location or '?'}); redirects are not followed"
    else:
        reason = f"owner's own request failed ({owner.error or f'status {owner.status}'}); refresh the owner session"
    return Result(spec, Verdict.SKIPPED, reason, owner)


def analyze(spec: RequestSpec, owner: Response, other: Response, anon: Response, cfg: Config) -> Result:
    if not owner.ok:
        return baseline_failed(spec, owner)

    base = content(owner.body, cfg.ignore_keys)
    # Markers that identify the owner and were actually in the owner's response.
    # Seeing one of them in someone else's response is the strongest signal there is.
    present = [m for m in cfg.owner.markers if m not in cfg.other.markers and m in base.text]

    sim_anon = sim_other = None
    if anon.ok:
        anon_content = content(anon.body, cfg.ignore_keys)
        sim_anon = similarity(base, anon_content)
        leaked = tuple(m for m in present if m in anon_content.text)
        if leaked:
            return Result(
                spec, Verdict.VULNERABLE, "owner's data returned with no credentials at all",
                owner, other, anon, None, sim_anon, leaked, "anonymous",
            )
        if sim_anon >= cfg.similarity_threshold:
            return Result(
                spec, Verdict.PUBLIC, "same response without credentials; confirm it is meant to be public",
                owner, other, anon, None, sim_anon,
            )

    if not other.ok:
        why = other.error or f"status {other.status}"
        return Result(spec, Verdict.ENFORCED, f"other user refused ({why})", owner, other, anon, None, sim_anon)

    other_content = content(other.body, cfg.ignore_keys)
    sim_other = similarity(base, other_content)
    leaked = tuple(m for m in present if m in other_content.text)
    if leaked:
        return Result(
            spec, Verdict.VULNERABLE, "another user received the owner's data",
            owner, other, anon, sim_other, sim_anon, leaked, "other",
        )
    if sim_other >= cfg.similarity_threshold:
        hint = "; the URL names a specific object" if has_object_reference(spec.url) else ""
        return Result(
            spec, Verdict.SUSPECT, f"two users got the same response behind auth{hint}; shared data or missing check",
            owner, other, anon, sim_other, sim_anon,
        )
    return Result(
        spec, Verdict.DIFFERS, "other user got different content (own data, or an error inside a 2xx)",
        owner, other, anon, sim_other, sim_anon,
    )
