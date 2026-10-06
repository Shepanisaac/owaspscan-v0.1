"""Command-line interface with the safety gate."""
from __future__ import annotations

import argparse
import logging
import sys
from urllib.parse import urlparse

from . import __version__
from .checks import REGISTRY
from .config import ScanConfig
from .engine import ScanError, run_scan
from .reporting import render_console, write_json


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="owaspscan",
        description="Passive OWASP Top 10 checks. Only scan systems you are authorized to test.",
    )
    p.add_argument("target", nargs="?", help="URL to scan, e.g. https://example.com")
    p.add_argument("--i-have-permission", action="store_true",
                   help="Confirm you own the target or have written authorization to test it.")
    p.add_argument("--max-pages", type=int, default=25)
    p.add_argument("--delay", type=float, default=0.2, help="Seconds between crawl requests.")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE",
                   help="Session cookie for authenticated scans (repeatable).")
    p.add_argument("--checks", help="Comma-separated check ids (default: all).")
    p.add_argument("--json", metavar="PATH", help="Also write a JSON report.")
    p.add_argument("--list-checks", action="store_true")
    p.add_argument("--version", action="version", version=f"owaspscan {__version__}")
    return p


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_checks:
        for check_id, cls in REGISTRY.items():
            print(f"{check_id:16} {cls.category}  {cls.description}")
        return 0

    if not args.target:
        return _fail("a target URL is required")
    parsed = urlparse(args.target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return _fail("target must be a full http:// or https:// URL")
    if not args.i_have_permission:
        return _fail("refusing to scan without --i-have-permission "
                     "(only test systems you own or are authorized to test)")

    cookies = {}
    for item in args.cookie:
        name, sep, value = item.partition("=")
        if not sep or not name:
            return _fail(f"invalid --cookie '{item}', expected NAME=VALUE")
        cookies[name] = value

    config = ScanConfig(
        target=args.target,
        max_pages=args.max_pages,
        delay=args.delay,
        timeout=args.timeout,
        cookies=cookies,
        enabled_checks=[c.strip() for c in args.checks.split(",")] if args.checks else None,
    )

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    try:
        result = run_scan(config)
    except (ScanError, ValueError) as exc:
        return _fail(str(exc))

    print(render_console(result))
    if args.json:
        write_json(result, args.json)
        print(f"JSON report written to {args.json}")
    return 0
