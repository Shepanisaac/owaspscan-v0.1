"""A05: missing browser security headers on the landing page."""
from __future__ import annotations

from ..models import Finding, Severity
from .base import Check, ScanContext, register

SIMPLE = (
    ("Content-Security-Policy", Severity.MEDIUM,
     "Define a Content-Security-Policy to restrict script sources and reduce XSS impact."),
    ("X-Content-Type-Options", Severity.LOW, "Send 'X-Content-Type-Options: nosniff'."),
    ("Referrer-Policy", Severity.LOW,
     "Send a Referrer-Policy such as 'strict-origin-when-cross-origin'."),
)


@register
class SecurityHeadersCheck(Check):
    id = "security-headers"
    category = "A05"
    description = "Missing security headers (CSP, HSTS, clickjacking, nosniff)"

    def run(self, ctx: ScanContext) -> list[Finding]:
        page = ctx.landing
        headers = page.response.headers
        findings = []

        for name, severity, fix in SIMPLE:
            if name not in headers:
                findings.append(self.finding(
                    f"Missing {name} header", severity, page.url,
                    f"Response did not include {name}.", fix))

        csp = headers.get("Content-Security-Policy", "").lower()
        if "X-Frame-Options" not in headers and "frame-ancestors" not in csp:
            findings.append(self.finding(
                "No clickjacking protection", Severity.MEDIUM, page.url,
                "Neither X-Frame-Options nor CSP frame-ancestors is set.",
                "Send 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive."))

        if page.url.startswith("https://") and "Strict-Transport-Security" not in headers:
            findings.append(self.finding(
                "Missing Strict-Transport-Security header", Severity.MEDIUM, page.url,
                "HTTPS site does not send HSTS.",
                "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."))
        return findings
