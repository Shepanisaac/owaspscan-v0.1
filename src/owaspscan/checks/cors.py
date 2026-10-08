"""A05: CORS policies that trust untrusted origins (active: sends probes with a fake Origin)."""
from __future__ import annotations

from urllib.parse import urlparse

from ..models import Finding, Severity
from .base import Check, ScanContext, register

EVIL_ORIGIN = "https://evil.example"
MAX_URLS = 5  # distinct pages probed per scan


@register
class CorsCheck(Check):
    id = "cors"
    category = "A05"
    description = "CORS trusting arbitrary, null or look-alike origins"
    active = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        parts = urlparse(ctx.landing.url)
        origins = {
            "arbitrary": EVIL_ORIGIN,
            "null": "null",
            "look-alike": f"{parts.scheme}://{parts.hostname}.evil.example",
        }
        findings: list[Finding] = []
        reported: set[str] = set()

        for page in ctx.pages[:MAX_URLS]:
            for kind, origin in origins.items():
                if kind in reported or (kind == "look-alike" and "arbitrary" in reported):
                    continue
                response = ctx.probe(page.url, headers={"Origin": origin})
                if response is None:
                    if ctx.probes_used >= ctx.config.max_probes:
                        return findings  # probe budget spent
                    continue
                finding = self._assess(kind, origin, response.headers, page.url)
                if finding:
                    reported.add(kind)
                    findings.append(finding)
        return findings

    def _assess(self, kind, origin, headers, url) -> Finding | None:
        allowed = headers.get("access-control-allow-origin")
        credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
        evidence = (f"Sent Origin: {origin}; response had Access-Control-Allow-Origin: "
                    f"{allowed}, Access-Control-Allow-Credentials: {credentials}")

        if allowed == "*" and kind == "arbitrary":
            return self.finding(
                "CORS allows any origin (wildcard)", Severity.INFO, url, evidence,
                "Fine for public content; make sure no private data is served this way.")
        if allowed != origin:
            return None

        severity = Severity.HIGH if credentials else Severity.LOW
        titles = {
            "arbitrary": "CORS reflects any origin",
            "null": "CORS trusts the 'null' origin",
            "look-alike": "CORS trusts look-alike origins (weak origin matching)",
        }
        suffix = " with credentials" if credentials else ""
        return self.finding(
            titles[kind] + suffix, severity, url, evidence,
            "Allow only an explicit list of trusted origins, compare them exactly, "
            "and never combine reflected origins with Allow-Credentials.")
