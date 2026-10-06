"""Runs the crawl and the selected checks, then merges the findings."""
from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from .checks import REGISTRY
from .checks.base import ScanContext
from .config import ScanConfig
from .crawler import crawl
from .models import Finding

log = logging.getLogger(__name__)


class ScanError(Exception):
    """Raised when a scan cannot run at all (e.g. target unreachable)."""


@dataclass
class ScanResult:
    target: str
    pages_scanned: int
    findings: list[Finding]


def run_scan(config: ScanConfig, transport: httpx.BaseTransport | None = None) -> ScanResult:
    ids = config.enabled_checks or list(REGISTRY)
    unknown = [i for i in ids if i not in REGISTRY]
    if unknown:
        raise ValueError(f"Unknown check(s): {', '.join(unknown)}")

    with httpx.Client(
        timeout=config.timeout,
        follow_redirects=True,
        cookies=config.cookies,
        headers={"User-Agent": config.user_agent},
        transport=transport,
    ) as client:
        pages = crawl(client, config)
        if not pages:
            raise ScanError(f"Could not reach {config.target}")
        ctx = ScanContext(config, client, pages)

        findings: list[Finding] = []
        for check_id in ids:
            try:
                findings.extend(REGISTRY[check_id]().run(ctx))
            except Exception:  # one broken check must never kill the scan
                log.exception("Check %s failed; skipping", check_id)

    unique = list(dict.fromkeys(findings))  # dedupe, keep order
    unique.sort(key=lambda f: (-f.severity, f.category, f.url, f.title))
    return ScanResult(config.target, len(pages), unique)
