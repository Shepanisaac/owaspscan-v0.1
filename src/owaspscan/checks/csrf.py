"""A01: state-changing forms without a visible CSRF token or SameSite cookie (passive).

Inspects forms the crawler already discovered; sends no extra requests.
"""
from __future__ import annotations

import re
from http.cookies import CookieError, SimpleCookie

from ..models import Finding, Severity
from .base import Check, ScanContext, register

TOKEN_FIELD = re.compile(r"csrf|xsrf|authenticity|_token|nonce", re.IGNORECASE)
STATE_CHANGING = re.compile(
    r"delete|remove|update|edit|change|transfer|pay|checkout|submit|save|create|add|cancel",
    re.IGNORECASE)


def _has_strict_samesite(pages) -> bool:
    """True if any Set-Cookie header observed during the crawl has SameSite=Lax/Strict."""
    for page in pages:
        for raw in page.response.headers.get_list("set-cookie"):
            try:
                jar = SimpleCookie()
                jar.load(raw)
            except CookieError:
                continue
            for morsel in jar.values():
                if morsel["samesite"].lower() in ("strict", "lax"):
                    return True
    return False


@register
class CsrfCheck(Check):
    id = "csrf"
    category = "A01"
    description = "State-changing forms with no visible CSRF token and no SameSite cookie"

    def run(self, ctx: ScanContext) -> list[Finding]:
        samesite_seen = _has_strict_samesite(ctx.pages)
        findings = []
        reported: set[tuple[str, str]] = set()

        for page in ctx.pages:
            for form in page.forms:
                if form.method != "POST":
                    continue
                if not STATE_CHANGING.search(form.action) and not any(
                        STATE_CHANGING.search(name) for name, _ in form.fields):
                    continue
                if any(TOKEN_FIELD.search(name) for name, _ in form.fields):
                    continue
                key = (form.action, form.method)
                if key in reported:
                    continue
                reported.add(key)
                severity = Severity.LOW if samesite_seen else Severity.MEDIUM
                note = (" A strict SameSite cookie was observed, which reduces the risk."
                        if samesite_seen else "")
                findings.append(self.finding(
                    "State-changing form with no CSRF token", severity, form.action,
                    f"POST form at {form.action} has no field matching csrf/token/nonce.{note}",
                    "Add a per-session, unpredictable CSRF token field checked on submit, "
                    "and set the session cookie's SameSite attribute to Lax or Strict."))
        return findings
