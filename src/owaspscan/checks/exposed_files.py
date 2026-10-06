"""A05: sensitive files reachable on the web root, confirmed by content signature."""
from __future__ import annotations

import re
from dataclasses import dataclass

import httpx

from ..models import Finding, Severity
from .base import Check, ScanContext, register


@dataclass(frozen=True)
class Probe:
    path: str
    signature: re.Pattern
    title: str
    severity: Severity
    allow_html: bool = False


PROBES = (
    Probe("/.git/HEAD", re.compile(r"^ref:\s*refs/", re.M), "Git repository exposed", Severity.HIGH),
    Probe("/.env", re.compile(r"^[A-Z][A-Z0-9_]*=", re.M), "Environment file exposed", Severity.HIGH),
    Probe("/backup.sql", re.compile(r"CREATE TABLE|INSERT INTO", re.I), "Database dump exposed", Severity.HIGH),
    Probe("/server-status", re.compile(r"Apache Server Status"), "Apache server-status exposed",
          Severity.MEDIUM, allow_html=True),
    Probe("/phpinfo.php", re.compile(r"phpinfo\(\)|PHP Version"), "phpinfo page exposed",
          Severity.MEDIUM, allow_html=True),
)


@register
class ExposedFilesCheck(Check):
    id = "exposed-files"
    category = "A05"
    description = "Exposed .git, .env, backups and debug pages"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        for probe in PROBES:
            url = ctx.origin + probe.path
            try:
                response = ctx.client.get(url)
            except httpx.HTTPError:
                continue
            is_html = "text/html" in response.headers.get("content-type", "")
            if response.status_code != 200 or (is_html and not probe.allow_html):
                continue  # HTML here is usually a soft-404 / SPA fallback
            if probe.signature.search(response.text[:5000]):
                findings.append(self.finding(
                    probe.title, probe.severity, url,
                    f"GET {probe.path} returned 200 with matching content.",
                    "Remove the file from the web root and block access in server config."))
        return findings
