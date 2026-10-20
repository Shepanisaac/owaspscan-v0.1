"""A03: HTTP response splitting / header injection via a parameter whose value survives
into a response header with its CR/LF characters intact (active, GET only).

Sends a payload ending in a CR/LF sequence followed by a distinctive marker header name.
If that marker header actually shows up as its own header in the response, raw newlines
reached code that builds a response header from this input — a confirmed finding, not a
heuristic, since there's no other way that header name would appear.
"""
from __future__ import annotations

from ..models import Finding, Severity
from .base import Check, ScanContext, register

MARKER_HEADER = "X-Owaspscan-Crlf-Test"
PAYLOAD = f"owaspscan\r\n{MARKER_HEADER}: injected"


@register
class CrlfInjectionCheck(Check):
    id = "crlf-injection"
    category = "A03"
    description = "Parameter value whose CR/LF characters survive into a response header"
    active = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for point in ctx.injection_points:
            response = ctx.probe(point.url, params=point.request_params(PAYLOAD))
            if response is None:
                if ctx.probes_used >= ctx.config.max_probes:
                    break
                continue
            if MARKER_HEADER.lower() in {k.lower() for k in response.headers.keys()}:
                findings.append(self.finding(
                    f"HTTP response splitting via parameter '{point.param}'", Severity.HIGH,
                    point.url,
                    f"Setting {point.param} to a value containing a CR/LF sequence produced "
                    f"a response with an injected '{MARKER_HEADER}' header — raw newline "
                    "characters from this parameter reached code building a response "
                    "header. This can be used for cache poisoning, reflected XSS via an "
                    "injected header, or session fixation via an injected Set-Cookie.",
                    "Strip or reject CR/LF characters from user input before using it to "
                    "build any response header (redirects, cookies, custom headers); use "
                    "your framework's header-setting APIs rather than concatenating raw "
                    "strings into a header line."))
        return findings
