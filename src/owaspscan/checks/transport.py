"""A02: is the site served over HTTPS?"""
from __future__ import annotations

from urllib.parse import urlparse

from ..models import Finding, Severity
from .base import Check, ScanContext, register


@register
class TransportCheck(Check):
    id = "transport"
    category = "A02"
    description = "Site served over plain HTTP"

    def run(self, ctx: ScanContext) -> list[Finding]:
        page = ctx.landing
        if urlparse(page.url).scheme == "https":
            return []
        return [self.finding(
            "Site is served over unencrypted HTTP", Severity.MEDIUM, page.url,
            f"Landing page final URL is {page.url}; no redirect to HTTPS observed.",
            "Serve the site over HTTPS and redirect all HTTP traffic to it.")]
