"""A05: the server trusting the Host (or X-Forwarded-Host) request header and echoing it
back into a redirect or into the page itself (active, GET only). This matters because an
app that builds absolute URLs — password-reset links, canonical tags, cache keys — from
whichever Host header the client sent can be tricked into generating links that point at
an attacker's domain instead of its own, enabling cache poisoning or credential-stealing
password-reset links. Only the landing page is tested; this is a server/app-level
configuration question, not a per-page one.
"""
from __future__ import annotations

from ..models import Finding, Severity
from .base import Check, ScanContext, register

TEST_HOST = "owaspscan-host-header-test.invalid"
MAX_SCAN_CHARS = 50_000
TECHNIQUES = (
    ("Host header", {"Host": TEST_HOST}),
    ("X-Forwarded-Host header", {"X-Forwarded-Host": TEST_HOST}),
)


@register
class HostHeaderCheck(Check):
    id = "host-header"
    category = "A05"
    description = "Host/X-Forwarded-Host header trusted and echoed into redirects or pages"
    active = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        url = ctx.landing.url
        for label, headers in TECHNIQUES:
            response = ctx.probe(url, headers=headers, follow_redirects=False)
            if response is None:
                if ctx.probes_used >= ctx.config.max_probes:
                    break
                continue
            finding = self._assess(response, url, label)
            if finding:
                findings.append(finding)
        return findings

    def _assess(self, response, url, label) -> Finding | None:
        location = response.headers.get("location", "")
        if TEST_HOST in location:
            return self.finding(
                f"Host header injection via {label} (redirect)", Severity.MEDIUM, url,
                f"Sending a {label} of '{TEST_HOST}' produced a redirect to {location}.",
                "Build redirect targets from a fixed, server-side configured hostname, "
                "never from the Host or X-Forwarded-Host request header.")

        if response.status_code == 200 and "html" in response.headers.get("content-type", ""):
            if TEST_HOST in response.text[:MAX_SCAN_CHARS]:
                return self.finding(
                    f"Host header injection via {label} (reflected in page)", Severity.MEDIUM,
                    url,
                    f"Sending a {label} of '{TEST_HOST}' produced a page containing that "
                    "value, meaning it was used to build a link, form action, canonical "
                    "tag, or other URL in the response.",
                    "Build absolute URLs (canonical tags, asset links, form actions, "
                    "password-reset links) from a fixed, server-side configured hostname, "
                    "never from the Host or X-Forwarded-Host request header.")
        return None
