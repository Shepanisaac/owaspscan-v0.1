"""A08: cross-origin <script>/<link> tags with no Subresource Integrity (SRI) check.
Passive — reads what the crawler already fetched, sends no extra requests.

A page that loads a script or stylesheet from someone else's server, with no `integrity`
attribute, is trusting that server completely: if it's ever compromised (or a CDN account
hijacked), this page runs whatever it's handed next time, no questions asked. `integrity`
pins the exact expected bytes; the browser refuses to use anything else.
"""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

from ..models import Finding, Severity
from .base import Check, ScanContext, register


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def _is_stylesheet(tag) -> bool:
    rel = tag.get("rel") or []
    rel = rel if isinstance(rel, list) else [rel]
    return any(r.lower() == "stylesheet" for r in rel)


@register
class SRICheck(Check):
    id = "sri"
    category = "A08"
    description = "Cross-origin scripts/stylesheets with no Subresource Integrity check"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()  # (tag name, resolved src) already reported

        for page in ctx.pages:
            if page.soup is None:
                continue
            for tag_name, attr in (("script", "src"), ("link", "href")):
                for tag in page.soup.find_all(tag_name):
                    if tag_name == "link" and not _is_stylesheet(tag):
                        continue
                    raw = tag.get(attr)
                    if not raw:
                        continue
                    resolved = urljoin(page.url, raw)
                    if not resolved.startswith(("http://", "https://")):
                        continue  # data:, blob:, etc. — nothing to pin
                    if _same_origin(resolved, page.url):
                        continue  # same-origin: no third party being trusted

                    key = (tag_name, resolved)
                    if key in seen:
                        continue
                    seen.add(key)

                    finding = self._assess(tag, tag_name, attr, resolved, page.url)
                    if finding:
                        findings.append(finding)
        return findings

    def _assess(self, tag, tag_name, attr, resolved, url) -> Finding | None:
        integrity = tag.get("integrity")
        crossorigin = tag.get("crossorigin")
        if not integrity:
            return self.finding(
                f"Cross-origin {tag_name} with no Subresource Integrity check",
                Severity.MEDIUM, url,
                f'<{tag_name} {attr}="{resolved}"> has no integrity attribute. If that '
                "external host is ever compromised, this page will run whatever it serves "
                "next, with no verification at all.",
                'Add an integrity="sha384-..." attribute (most CDNs publish the hash '
                'alongside the snippet) and crossorigin="anonymous", or self-host the file.')
        if not crossorigin:
            return self.finding(
                f"Cross-origin {tag_name} has integrity but no crossorigin attribute",
                Severity.LOW, url,
                f'<{tag_name} {attr}="{resolved}"> sets integrity but not crossorigin, which '
                "makes some browsers skip the integrity check entirely for cross-origin "
                "requests.",
                'Add crossorigin="anonymous" alongside the existing integrity attribute.')
        return None
