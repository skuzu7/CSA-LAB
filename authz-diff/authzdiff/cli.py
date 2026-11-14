from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path

from . import __version__
from .analyze import Result, Verdict, analyze, baseline_failed
from .config import SAFE_METHODS, Config, ConfigError, load_config
from .har import HarError, load_har, select
from .models import RequestSpec
from .replay import Client
from .report import render_markdown, render_table, summary_line, to_json

EXIT_OK, EXIT_ERROR, EXIT_FINDINGS = 0, 1, 2


def run(cfg: Config, specs: list[RequestSpec], client: Client, on_result: Callable[[Result], None] | None = None) -> list[Result]:
    """Replay each request as owner, anonymous and other, and judge the three answers."""
    results = []
    for spec in specs:
        owner = client.send(spec, cfg.owner)
        if owner.ok:
            anon = client.send(spec, None)
            other = client.send(spec, cfg.other)
            result = analyze(spec, owner, other, anon, cfg)
        else:
            # No baseline, nothing to compare: do not spend two more requests.
            result = baseline_failed(spec, owner)
        results.append(result)
        if on_result:
            on_result(result)
    return results


def _save_bodies(directory: Path, results: list[Result]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for index, r in enumerate(results, 1):
        slug = re.sub(r"[^A-Za-z0-9]+", "_", f"{r.request.method}_{r.request.path}").strip("_")[:80]
        for who, response in (("owner", r.owner), ("other", r.other), ("anonymous", r.anon)):
            if response is not None and response.status:
                (directory / f"{index:03d}_{slug}.{who}.{response.status}.body").write_bytes(response.body)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="authzdiff",
        description="Replay requests captured as one user as a second user and with no credentials, "
        "and report where the server hands over the first user's data. "
        "Only for systems you are authorized to test, using accounts you control.",
    )
    p.add_argument("-c", "--config", required=True, help="TOML file with scope, identities and settings")
    p.add_argument("--har", action="append", default=[], metavar="FILE", help="HAR capture of the owner's session (repeatable)")
    p.add_argument("--methods", help="comma-separated methods to replay, overriding the config (default GET)")
    p.add_argument("--allow-state-changing", action="store_true", help="required to replay anything other than GET/HEAD/OPTIONS")
    p.add_argument("--dry-run", action="store_true", help="list what would be sent and exit")
    p.add_argument("--json", metavar="FILE", help="write results as JSON")
    p.add_argument("--report", metavar="FILE", help="write a Markdown report")
    p.add_argument("--save-bodies", metavar="DIR", help="save raw response bodies for manual review (may contain private data)")
    p.add_argument("--proxy", metavar="URL", help="send traffic through a proxy, e.g. http://127.0.0.1:8080")
    p.add_argument("--cafile", metavar="PEM", help="extra CA certificate to trust, e.g. your intercepting proxy's")
    p.add_argument("--version", action="version", version=f"authzdiff {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        cfg = load_config(args.config)
        if args.methods:
            cfg = dataclasses.replace(cfg, methods=frozenset(m.strip().upper() for m in args.methods.split(",") if m.strip()))
        specs = list(cfg.requests)
        for path in args.har:
            specs += load_har(path)
    except (ConfigError, HarError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    unsafe = sorted(cfg.methods - SAFE_METHODS)
    if unsafe and not args.allow_state_changing:
        print(
            f"error: {', '.join(unsafe)} can change or delete data when replayed as another user. "
            "Pass --allow-state-changing if the program's rules permit it and the data is yours to lose.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    chosen, dropped = select(specs, cfg)
    skipped = f" ({', '.join(f'{n} {why}' for why, n in dropped.items())} not tested)" if dropped else ""
    print(f"{len(chosen)} request(s) to test{skipped}", file=sys.stderr)
    if not chosen:
        print("error: nothing to test. Check [scope] hosts, the enabled methods and the HAR file.", file=sys.stderr)
        return EXIT_ERROR

    if args.dry_run:
        for spec in chosen:
            print(f"{spec.method} {spec.url}")
        return EXIT_OK

    if not cfg.owner.markers:
        print(
            "warning: [identities.owner] has no markers. Without strings that identify the owner "
            "(email, name, account id) nothing can be confirmed as VULNERABLE, only SUSPECT.",
            file=sys.stderr,
        )
    if unsafe:
        print(f"warning: replaying state-changing methods: {', '.join(unsafe)}", file=sys.stderr)

    try:
        client = Client(cfg, proxy=args.proxy, cafile=args.cafile)
    except OSError as exc:  # unreadable or invalid --cafile
        print(f"error: cannot load --cafile: {exc}", file=sys.stderr)
        return EXIT_ERROR
    progress = sys.stderr.isatty()

    def on_result(result: Result) -> None:
        if progress:
            print(f"\r\033[K{result.verdict.value:<10} {result.request.method} {result.request.path[:70]}", end="", file=sys.stderr)

    try:
        results = run(cfg, chosen, client, on_result)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_ERROR
    if progress:
        print("\r\033[K", end="", file=sys.stderr)

    print(render_table(results, color=sys.stdout.isatty()))
    print(f"\n{summary_line(results)} ({client.sent} requests sent)", file=sys.stderr)

    if args.json:
        Path(args.json).write_text(json.dumps(to_json(results, cfg, dropped), indent=2) + "\n", encoding="utf-8")
    if args.report:
        Path(args.report).write_text(render_markdown(results, cfg, dropped), encoding="utf-8")
    if args.save_bodies:
        _save_bodies(Path(args.save_bodies), results)

    if all(r.verdict is Verdict.SKIPPED for r in results):
        # A run that compared nothing must not look like a clean pass.
        print(
            "error: no request succeeded as the owner, so nothing was tested. "
            "Check the owner's credentials and that the target is reachable.",
            file=sys.stderr,
        )
        return EXIT_ERROR
    return EXIT_FINDINGS if any(r.verdict is Verdict.VULNERABLE for r in results) else EXIT_OK
