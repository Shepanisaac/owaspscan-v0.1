"""A05: server/framework details leaked in response headers."""
from __future__ import annotations

import re

from ..models import Finding, Severity
from .base import Check, ScanContext, register

HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator")
VERSION = re.compile(r"\d+\.\d+")


@register
class DisclosureCheck(Check):
    id = "disclosure"
    category = "A05"
    description = "Technology and version disclosure in headers"

    def run(self, ctx: ScanContext) -> list[Finding]:
        page = ctx.landing
        findings = []
        for name in HEADERS:
            value = page.response.headers.get(name)
            if not value:
                continue
            severity = Severity.LOW if VERSION.search(value) else Severity.INFO
            findings.append(self.finding(
                f"{name} header discloses technology", severity, page.url,
                f"{name}: {value}",
                "Remove or genericize this header so attackers cannot target known versions."))
        return findings
