"""A05: a page containing a login/password form, served with no Cache-Control: no-store.
Passive — reads what the crawler already fetched, sends no extra requests.

A shared or public computer's browser (or an intermediate proxy cache) can retain a cached
copy of a sensitive page after the user logs out or walks away, letting the next person
hit "back" and see it. This only looks for a password field as the sensitivity signal — it
cannot know which other pages (an account dashboard, an order history) are sensitive
without a cookie/header to compare against, which is a real, documented limitation.
"""
from __future__ import annotations

from ..models import Finding, Severity
from .base import Check, ScanContext, register


def _has_password_field(page) -> bool:
    if page.soup is None:
        return False
    return any((field.get("type") or "").lower() == "password"
               for field in page.soup.find_all("input"))


def _has_no_store(headers) -> bool:
    value = headers.get("cache-control", "").lower()
    return "no-store" in value


@register
class CacheControlCheck(Check):
    id = "cache-control"
    category = "A05"
    description = "Login/password form served without Cache-Control: no-store"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for page in ctx.pages:
            if not _has_password_field(page):
                continue
            if _has_no_store(page.response.headers):
                continue
            cache_control = page.response.headers.get("cache-control", "(none)")
            findings.append(self.finding(
                "Login page missing Cache-Control: no-store", Severity.MEDIUM, page.url,
                f"This page has a password field but sent Cache-Control: {cache_control}. "
                "A shared or public computer's browser (or a caching proxy) can retain this "
                "page after the user leaves, letting the next person hit 'back' and see it.",
                "Send 'Cache-Control: no-store' on any page that renders a login form or "
                "other sensitive content."))
        return findings
