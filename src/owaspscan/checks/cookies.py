"""A02/A07: cookie attribute checks (Secure, HttpOnly, SameSite)."""
from __future__ import annotations

import re
from http.cookies import CookieError, SimpleCookie

from ..models import Finding, Severity
from .base import Check, ScanContext, register

SESSION_LIKE = re.compile(r"sess|auth|token|jwt|sid", re.IGNORECASE)


@register
class CookieCheck(Check):
    id = "cookies"
    category = "A07"
    description = "Cookies missing Secure, HttpOnly or SameSite"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for page in ctx.pages:
            for raw in page.response.headers.get_list("set-cookie"):
                try:
                    jar = SimpleCookie()
                    jar.load(raw)
                except CookieError:
                    continue
                for name, morsel in jar.items():
                    if name in seen:
                        continue
                    seen.add(name)
                    sensitive = bool(SESSION_LIKE.search(name))
                    findings += self._inspect(name, morsel, page.url, sensitive)
        return findings

    def _inspect(self, name, morsel, url, sensitive) -> list[Finding]:
        out = []
        high = Severity.MEDIUM if sensitive else Severity.LOW
        if url.startswith("https://") and not morsel["secure"]:
            out.append(self.finding(
                f"Cookie '{name}' missing Secure flag", high, url,
                "Cookie can be sent over unencrypted connections.",
                "Add the Secure attribute."))
        if not morsel["httponly"]:
            out.append(self.finding(
                f"Cookie '{name}' missing HttpOnly flag", high, url,
                "Cookie is readable from JavaScript.", "Add the HttpOnly attribute."))
        if not morsel["samesite"]:
            out.append(self.finding(
                f"Cookie '{name}' missing SameSite attribute", Severity.LOW, url,
                "Cookie is sent on cross-site requests by default.",
                "Add SameSite=Lax or SameSite=Strict."))
        return out
