"""A01: open redirect via a parameter that controls where the page sends the visitor
(active, GET only). Only parameters whose NAME looks redirect-related are probed, to keep
probe usage low and avoid false alarms on unrelated parameters.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..models import Finding, Severity
from .base import Check, ScanContext, register

TEST_HOST = "owaspscan-redirect-test.invalid"
TEST_URL = f"https://{TEST_HOST}/"

NAME_HINTS = (
    "next", "url", "redirect", "redirecturl", "redirect_uri", "return", "returnurl",
    "returnto", "continue", "dest", "destination", "go", "target", "callback", "rurl",
)

META_REFRESH = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*content=["\'][^"\']*url=([^"\'>\s]+)',
    re.IGNORECASE)
JS_REDIRECT = re.compile(
    r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


def _looks_redirect_like(name: str) -> bool:
    lowered = re.sub(r"[^a-z]", "", name.lower())
    return any(hint in lowered for hint in NAME_HINTS)


def _targets_test_host(url: str) -> bool:
    try:
        return urlsplit(url).hostname == TEST_HOST
    except ValueError:
        return False


@register
class OpenRedirectCheck(Check):
    id = "open-redirect"
    category = "A01"
    description = "Parameter-controlled redirect to an external site"
    active = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for point in ctx.injection_points:
            if not _looks_redirect_like(point.param):
                continue
            response = ctx.probe(point.url, params=point.request_params(TEST_URL),
                                 follow_redirects=False)
            if response is None:
                if ctx.probes_used >= ctx.config.max_probes:
                    break  # probe budget spent
                continue
            finding = self._assess(response, point)
            if finding:
                findings.append(finding)
        return findings

    def _assess(self, response, point) -> Finding | None:
        if 300 <= response.status_code < 400:
            location = response.headers.get("location", "")
            if _targets_test_host(location):
                return self.finding(
                    f"Open redirect via parameter '{point.param}'", Severity.MEDIUM, point.url,
                    f"Setting {point.param}={TEST_URL} produced HTTP {response.status_code} "
                    f"redirecting to {location}.",
                    "Only redirect to a fixed allow-list of destinations, or require a "
                    "same-site relative path and reject absolute URLs / protocol-relative '//'.")
            return None  # redirected, but not to our test host: not attacker-controlled

        if response.status_code == 200 and "html" in response.headers.get("content-type", ""):
            for pattern in (META_REFRESH, JS_REDIRECT):
                match = pattern.search(response.text)
                if match and _targets_test_host(match.group(1)):
                    return self.finding(
                        f"Client-side open redirect via parameter '{point.param}'",
                        Severity.LOW, point.url,
                        f"Setting {point.param}={TEST_URL} produced a page that redirects to "
                        f"it via {'meta refresh' if pattern is META_REFRESH else 'JavaScript'}.",
                        "Validate the destination server-side before redirecting; only allow "
                        "same-site relative paths.")
        return None
