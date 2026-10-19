"""A05: dangerous or unnecessary HTTP methods left enabled (active — sends OPTIONS and
TRACE requests, neither of which has side effects per the HTTP spec, but both are outside
the plain GET crawl, so this only runs with --active like the other active checks).

Only the landing page is tested; this is a server/vhost-level configuration question, not
a per-page one, so testing every crawled page would just burn probe budget for no benefit.
"""
from __future__ import annotations

import time

import httpx

from ..models import Finding, Severity
from .base import Check, ScanContext, register

# Methods that, if genuinely usable without authentication, would let a client modify or
# tunnel through the server. The Allow/Access-Control-Allow-Methods header only advertises
# what the server is configured to route, not proof any of these actually succeed
# unauthenticated — that's why this is reported as LOW, advisory evidence.
DANGEROUS_METHODS = ("PUT", "DELETE", "CONNECT")


@register
class HttpMethodsCheck(Check):
    id = "http-methods"
    category = "A05"
    description = "Dangerous or unnecessary HTTP methods left enabled (TRACE, verb tampering)"
    active = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        url = ctx.landing.url

        options_resp = self._request(ctx, "OPTIONS", url)
        if options_resp is not None:
            finding = self._assess_options(options_resp, url)
            if finding:
                findings.append(finding)

        trace_resp = self._request(ctx, "TRACE", url)
        if trace_resp is not None and trace_resp.status_code == 200:
            findings.append(self.finding(
                "TRACE method is enabled", Severity.MEDIUM, url,
                f"A TRACE request to {url} returned HTTP 200 instead of being rejected.",
                "Disable the TRACE method (and TRACK on IIS) at the server/vhost level; no "
                "web application needs it, and leaving it on enables cross-site tracing "
                "(XST) attacks that can help an attacker read cookies a browser would "
                "otherwise protect with HttpOnly."))
        return findings

    def _assess_options(self, response, url) -> Finding | None:
        allow = (response.headers.get("allow", "")
                 or response.headers.get("access-control-allow-methods", ""))
        allowed = {m.strip().upper() for m in allow.split(",") if m.strip()}
        risky = sorted(allowed & set(DANGEROUS_METHODS))
        if not risky:
            return None
        return self.finding(
            f"OPTIONS advertises potentially dangerous method(s): {', '.join(risky)}",
            Severity.LOW, url,
            f"Allow header: {allow or '(none)'}. This only shows what the server is "
            "configured to route to, not that it succeeds without authentication — "
            "verify manually before treating this as confirmed.",
            "If these methods aren't intentionally exposed as part of a REST API, "
            "disable them at the server/framework level, or require authentication "
            "and proper authorization for anything that modifies state.")

    def _request(self, ctx: ScanContext, method: str, url: str) -> httpx.Response | None:
        if ctx.probes_used >= ctx.config.max_probes:
            return None
        ctx.probes_used += 1
        time.sleep(ctx.config.delay)
        try:
            return ctx.client.request(method, url)
        except httpx.HTTPError:
            return None
