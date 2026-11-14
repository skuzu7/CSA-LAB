"""Terminal table, JSON and Markdown output. Credentials are never written anywhere."""

from __future__ import annotations

import re
import shlex
from collections import Counter
from datetime import datetime, timezone

from . import __version__
from .analyze import SEVERITY, Result, Verdict, has_object_reference
from .config import Config
from .models import Response

_COLORS = {
    Verdict.VULNERABLE: "\033[1;31m",
    Verdict.SUSPECT: "\033[33m",
    Verdict.PUBLIC: "\033[36m",
    Verdict.ENFORCED: "\033[32m",
    Verdict.SKIPPED: "\033[2m",
}


def _status(response: Response | None) -> str:
    if response is None:
        return "-"
    return "ERR" if response.status == 0 else str(response.status)


def _sim(value: float | None) -> str:
    return "-" if value is None else f"{value:.2f}"


def ordered(results: list[Result]) -> list[Result]:
    return sorted(results, key=lambda r: SEVERITY.index(r.verdict))


def render_table(results: list[Result], color: bool = False) -> str:
    header = ("VERDICT", "METHOD", "PATH", "OWNER", "OTHER", "ANON", "SIM", "NOTE")
    rows = []
    for r in ordered(results):
        path = r.request.path if len(r.request.path) <= 60 else r.request.path[:57] + "..."
        note = r.reason + (f" [{', '.join(r.leaked_markers)}]" if r.leaked_markers else "")
        shown_sim = r.similarity_anon if r.leaked_to == "anonymous" or r.verdict is Verdict.PUBLIC else r.similarity_other
        rows.append((r.verdict.value, r.request.method, path, _status(r.owner), _status(r.other), _status(r.anon), _sim(shown_sim), note))
    widths = [max(len(str(row[i])) for row in [header, *rows]) for i in range(len(header) - 1)]

    def line(row, paint: str = "") -> str:
        cells = [str(cell).ljust(width) for cell, width in zip(row, widths)] + [row[-1]]
        if paint:
            cells[0] = f"{paint}{cells[0]}\033[0m"
        return "  ".join(cells).rstrip()

    out = [line(header), line(tuple("-" * w for w in widths) + ("----",))]
    for row, r in zip(rows, ordered(results)):
        out.append(line(row, _COLORS.get(r.verdict, "") if color else ""))
    return "\n".join(out)


def summary_line(results: list[Result]) -> str:
    counts = Counter(r.verdict for r in results)
    return ", ".join(f"{counts[v]} {v.value.lower()}" for v in SEVERITY if counts[v])


def _response_json(response: Response | None) -> dict | None:
    if response is None:
        return None
    out = {"status": response.status, "bytes": len(response.body), "content_type": response.content_type}
    if response.location:
        out["location"] = response.location
    if response.error:
        out["error"] = response.error
    return out


def to_json(results: list[Result], cfg: Config, dropped: Counter) -> dict:
    return {
        "tool": f"authzdiff {__version__}",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scope": list(cfg.scope_hosts),
        "identities": {"owner": cfg.owner.name, "other": cfg.other.name},
        "dropped": dict(dropped),
        "results": [
            {
                "verdict": r.verdict.value,
                "reason": r.reason,
                "method": r.request.method,
                "url": r.request.url,
                "leaked_markers": list(r.leaked_markers),
                "leaked_to": r.leaked_to or None,
                "similarity_other": r.similarity_other,
                "similarity_anonymous": r.similarity_anon,
                "owner": _response_json(r.owner),
                "other": _response_json(r.other),
                "anonymous": _response_json(r.anon),
            }
            for r in ordered(results)
        ],
    }


def _placeholder(identity_name: str, header: str) -> str:
    slug = re.sub(r"[^A-Z0-9]+", "_", f"{identity_name}_{header}".upper()).strip("_")
    return f"<{slug}>"


def curl_command(result: Result, cfg: Config) -> str:
    """A reproduction command with placeholders where the credentials go."""
    spec = result.request
    parts = ["curl", "-i"]
    if spec.method != "GET":
        parts += ["-X", spec.method]
    if result.leaked_to != "anonymous":
        for header in cfg.other.headers:
            parts += ["-H", f"{header}: {_placeholder(cfg.other.name, header)}"]
    if spec.body is not None:
        content_type = next((v for k, v in spec.headers if k.lower() == "content-type"), "")
        if content_type:
            parts += ["-H", f"Content-Type: {content_type}"]
        parts += ["--data-raw", spec.body.decode("utf-8", "replace")]
    parts.append(spec.url)
    return " ".join(shlex.quote(p) for p in parts)


def _weakness(result: Result) -> str:
    if result.leaked_to == "anonymous":
        return "CWE-306 Missing Authentication for Critical Function"
    if has_object_reference(result.request.url):
        return "CWE-639 Authorization Bypass Through User-Controlled Key (IDOR / BOLA, OWASP API1:2023)"
    return "CWE-862 Missing Authorization (check for BFLA, OWASP API5:2023)"


def _fix(result: Result) -> str:
    if result.leaked_to == "anonymous":
        return "Require authentication on this route, then apply the same ownership check as any other private resource."
    return (
        "On the server, check that the authenticated user owns or is explicitly allowed to access the "
        "referenced resource before returning or changing it. Deny by default and cover the rule with a test."
    )


def _evidence(result: Result, cfg: Config) -> list[str]:
    rows = [
        (f"owner (`{cfg.owner.name}`)", result.owner, None),
        (f"other (`{cfg.other.name}`)", result.other, result.similarity_other),
        ("anonymous", result.anon, result.similarity_anon),
    ]
    lines = ["| Sent as | Status | Bytes | Similarity to owner |", "|---|---|---|---|"]
    for label, response, sim in rows:
        size = "-" if response is None else str(len(response.body))
        lines.append(f"| {label} | {_status(response)} | {size} | {_sim(sim)} |")
    return lines


def render_markdown(results: list[Result], cfg: Config, dropped: Counter) -> str:
    results = ordered(results)
    counts = Counter(r.verdict for r in results)
    out = [
        "# Access control test report",
        "",
        f"- Generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC with authzdiff {__version__}",
        f"- Scope: {', '.join(f'`{h}`' for h in cfg.scope_hosts)}",
        f"- Accounts: owner `{cfg.owner.name}`, other `{cfg.other.name}` (both controlled by the tester; credentials are not recorded)",
        f"- Requests tested: {len(results)}" + (f" (not tested: {', '.join(f'{n} {why}' for why, n in dropped.items())})" if dropped else ""),
        "",
        "| Verdict | Count |",
        "|---|---|",
        *[f"| {v.value} | {counts[v]} |" for v in SEVERITY if counts[v]],
        "",
    ]

    findings = [r for r in results if r.verdict is Verdict.VULNERABLE]
    out.append("## Findings")
    out.append("")
    if not findings:
        out += ["No response carried the owner's marked data to another identity.", ""]
    for number, r in enumerate(findings, 1):
        who = "an unauthenticated client" if r.leaked_to == "anonymous" else f"a different user (`{cfg.other.name}`)"
        out += [
            f"### {number}. {r.request.method} {r.request.path}",
            "",
            f"The request was captured as `{cfg.owner.name}`. Replayed as {who}, the server answered "
            f"{_status(r.anon if r.leaked_to == 'anonymous' else r.other)} and the body contained data that identifies "
            f"`{cfg.owner.name}`: {', '.join(f'`{m}`' for m in r.leaked_markers)}.",
            "",
            f"- Weakness: {_weakness(r)}",
            "",
            *_evidence(r, cfg),
            "",
            "Reproduce:",
            "",
            "```bash",
            curl_command(r, cfg),
            "```",
            "",
            f"Suggested fix: {_fix(r)}",
            "",
        ]

    review = [r for r in results if r.verdict in (Verdict.SUSPECT, Verdict.PUBLIC)]
    if review:
        out += [
            "## Needs manual review",
            "",
            "These are not findings yet. Open the responses and decide whether the data is meant to be shared.",
            "",
            "| Verdict | Request | Similarity | Why |",
            "|---|---|---|---|",
        ]
        for r in review:
            sim = r.similarity_anon if r.verdict is Verdict.PUBLIC else r.similarity_other
            out.append(f"| {r.verdict.value} | `{r.request.method} {r.request.path}` | {_sim(sim)} | {r.reason} |")
        out.append("")

    rest = [r for r in results if r.verdict in (Verdict.DIFFERS, Verdict.ENFORCED, Verdict.SKIPPED)]
    if rest:
        out += ["## Other requests", "", "| Verdict | Request | Owner | Other | Anonymous | Note |", "|---|---|---|---|---|---|"]
        for r in rest:
            out.append(
                f"| {r.verdict.value} | `{r.request.method} {r.request.path}` | {_status(r.owner)} | "
                f"{_status(r.other)} | {_status(r.anon)} | {r.reason} |"
            )
        out.append("")
    return "\n".join(out)
