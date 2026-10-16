"""A10: whether a URL-shaped parameter makes the SERVER (not the browser) fetch it
(active, GET only). This is a heuristic, not a confirmed exploit: without a public
callback server to receive an out-of-band request, there is no way to be fully certain the
target application actually reached out anywhere — only signals that something unusual
happened server-side. Every finding here says so explicitly and should be treated as
"worth investigating manually", not proof of an exploitable SSRF.
"""
from __future__ import annotations

import re
import time

from ..models import Finding, Severity
from .base import Check, ScanContext, register

NAME_HINTS = (
    "url", "uri", "link", "src", "image", "img", "file", "path", "callback",
    "webhook", "endpoint", "feed", "proxy", "fetch", "remote", "target", "dest",
)

CONTROL_URL = "https://example.com/"
# (label, target) pairs to try once a parameter looks fetchable. Kept small and fixed so
# probe usage per parameter stays bounded: 1 control request + one per target below.
SSRF_TARGETS = (
    ("internal loopback", "http://127.0.0.1:18273/owaspscan-ssrf-probe"),
    ("cloud metadata service", "http://169.254.169.254/latest/meta-data/"),
)
# Strings that would only plausibly appear if cloud instance-metadata content leaked into
# the response — not proof by itself, but a strong signal when present.
METADATA_MARKERS = re.compile(
    r"ami-id|instance-id|computeMetadata|security-credentials", re.IGNORECASE)

TIMING_ABS_SECONDS = 2.0  # minimum extra delay before timing alone counts as a signal
TIMING_MULTIPLIER = 3.0   # and it must be at least this many times the control request


def _looks_fetchable(name: str) -> bool:
    lowered = re.sub(r"[^a-z]", "", name.lower())
    return any(hint in lowered for hint in NAME_HINTS)


@register
class SSRFCheck(Check):
    id = "ssrf"
    category = "A10"
    description = "Parameters that may cause the server itself to fetch an attacker-chosen URL"
    active = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for point in ctx.injection_points:
            if not _looks_fetchable(point.param):
                continue

            start = time.perf_counter()
            control = ctx.probe(point.url, params=point.request_params(CONTROL_URL))
            control_time = time.perf_counter() - start
            if control is None:
                if ctx.probes_used >= ctx.config.max_probes:
                    break
                continue
            if 300 <= control.status_code < 400:
                continue  # browser-side redirect: that's open-redirect's territory, not SSRF

            for label, target_url in SSRF_TARGETS:
                start = time.perf_counter()
                response = ctx.probe(point.url, params=point.request_params(target_url))
                elapsed = time.perf_counter() - start
                if response is None:
                    if ctx.probes_used >= ctx.config.max_probes:
                        return findings
                    continue
                finding = self._assess(response, point, label, target_url, elapsed, control_time)
                if finding:
                    findings.append(finding)
        return findings

    def _assess(self, response, point, label, target_url, elapsed, control_time) -> Finding | None:
        if 300 <= response.status_code < 400:
            return None  # reflected as a redirect, not fetched server-side

        content_type = response.headers.get("content-type", "")
        text = ""
        if "text" in content_type or "json" in content_type:
            try:
                text = response.text
            except UnicodeDecodeError:
                text = ""

        if METADATA_MARKERS.search(text):
            return self.finding(
                f"Possible SSRF via parameter '{point.param}' ({label})", Severity.HIGH,
                point.url,
                f"Setting {point.param}={target_url} produced a response whose body contains "
                "cloud-metadata-shaped content, suggesting the server fetched it itself.",
                "Validate and allow-list any server-side fetch target; block requests to "
                "loopback, link-local (169.254.0.0/16), and other private address ranges.")

        if elapsed - control_time >= TIMING_ABS_SECONDS and elapsed >= control_time * TIMING_MULTIPLIER:
            return self.finding(
                f"Possible SSRF via parameter '{point.param}' ({label}, unconfirmed)",
                Severity.INFO, point.url,
                f"Setting {point.param}={target_url} took {elapsed:.1f}s to respond vs "
                f"{control_time:.1f}s for an ordinary URL — consistent with (but not proof "
                "of) the server attempting its own outbound connection. No out-of-band "
                "canary server was used to confirm this; verify manually before treating it "
                "as a real finding.",
                "If this parameter triggers a server-side fetch, validate and allow-list the "
                "target and block requests to loopback/link-local/private address ranges.")
        return None
