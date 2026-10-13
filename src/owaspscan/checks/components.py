"""A06: vulnerable/outdated components, detected from version strings that already
appear in the page (script/link filenames, a generator meta tag) or in response headers
already collected during the crawl. Passive — reads what the crawler already fetched,
sends no extra requests.

This only catches a component when it *announces* its version somewhere visible. A
bundled/minified app built with a modern bundler (webpack, Vite) that inlines its
dependencies with no version string anywhere will show nothing — that is a real
limitation, not a bug, and is called out in the README.
"""
from __future__ import annotations

import re

from ..models import Finding, Severity
from .base import Check, ScanContext, register
from ._component_signatures import LIBRARIES, PLATFORMS

SEVERITY = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW, "INFO": Severity.INFO}

def _filename_pattern(key: str) -> re.Pattern:
    """Build a pattern for a dotted/hyphenated key (e.g. "jquery-ui", "jquery.migrate")
    that matches either separator in the real filename, followed by a dotted version,
    e.g. "jquery-ui-1.11.4.min.js" or "jquery.migrate-3.3.2.min.js". A multi-word key's
    parts must appear in order; this deliberately does NOT let the plain "jquery" pattern
    swallow "jquery-ui-..." filenames, since each key only matches its own exact name.
    """
    parts = [re.escape(p) for p in re.split(r"[.-]", key)]
    return re.compile(r"[.@-]".join(parts) + r"[.@-]?v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)


# library key -> filename pattern capturing a dotted version, e.g. "jquery-3.2.1.min.js"
LIBRARY_FILENAME = {key: _filename_pattern(key) for key in LIBRARIES}

GENERATOR_META = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', re.IGNORECASE)
WORDPRESS_VERSION = re.compile(r"WordPress\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
PHP_HEADER_VERSION = re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
APACHE_HEADER_VERSION = re.compile(r"Apache/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)


def parse_version(text: str) -> tuple[int, ...] | None:
    """'3.2.1' -> (3, 2, 1). Returns None for anything that doesn't cleanly parse
    (e.g. 'latest', a hash, a malformed string) — never guess a version."""
    if not re.fullmatch(r"\d+(\.\d+){1,2}", text):
        return None
    return tuple(int(part) for part in text.split("."))


def is_vulnerable(version: tuple[int, ...], max_safe: tuple[int, ...] | None) -> bool:
    if max_safe is None:
        return True
    a = version + (0,) * (len(max_safe) - len(version))
    b = max_safe + (0,) * (len(version) - len(max_safe))
    return a < b


def worst_match(signatures, version: tuple[int, ...]):
    """The highest-severity signature this version falls under, if any."""
    hits = [s for s in signatures if is_vulnerable(version, s.max_safe)]
    return max(hits, key=lambda s: SEVERITY[s.severity]) if hits else None


@register
class ComponentsCheck(Check):
    id = "components"
    category = "A06"
    description = "Known-vulnerable or end-of-life library/platform versions"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()  # (component name, version) already reported

        for page in ctx.pages:
            for name, severity, evidence, remediation, key in self._from_page(page):
                if (name, evidence) in seen:
                    continue
                seen.add((name, evidence))
                findings.append(self.finding(
                    f"Outdated component: {name}", severity, page.url, evidence, remediation))
        return findings

    def _from_page(self, page):
        if page.soup is not None:
            for tag in page.soup.find_all(["script", "link"]):
                src = tag.get("src") or tag.get("href") or ""
                yield from self._check_libraries(src)

            meta = GENERATOR_META.search(page.response.text[:4000])
            if meta:
                yield from self._check_generator(meta.group(1))

        yield from self._check_headers(page.response.headers)

    def _check_libraries(self, src: str):
        for key, pattern in LIBRARY_FILENAME.items():
            match = pattern.search(src)
            if not match:
                continue
            version = parse_version(match.group(1))
            if version is None:
                continue
            hit = worst_match(LIBRARIES[key], version)
            if hit:
                yield (hit.name, SEVERITY[hit.severity],
                       self._evidence(hit, match.group(1), f"found in {src}"), self._fix(hit), key)

    def _check_generator(self, content: str):
        match = WORDPRESS_VERSION.search(content)
        if match:
            version = parse_version(match.group(1))
            if version:
                hit = worst_match(PLATFORMS["wordpress"], version)
                if hit:
                    yield (hit.name, SEVERITY[hit.severity],
                           self._evidence(hit, match.group(1), "from the generator meta tag"),
                           self._fix(hit), "wordpress")

    def _check_headers(self, headers):
        checks = (("server", APACHE_HEADER_VERSION, "apache", "the Server header"),
                  ("x-powered-by", PHP_HEADER_VERSION, "php", "the X-Powered-By header"))
        for header_name, pattern, key, source in checks:
            value = headers.get(header_name, "")
            match = pattern.search(value)
            if not match:
                continue
            version = parse_version(match.group(1))
            if version is None:
                continue
            hit = worst_match(PLATFORMS[key], version)
            if hit:
                yield (hit.name, SEVERITY[hit.severity],
                       self._evidence(hit, match.group(1), f"from {source} ({value})"),
                       self._fix(hit), key)

    @staticmethod
    def _evidence(sig, version: str, where: str) -> str:
        cve = f" ({sig.cve})" if sig.cve else ""
        return f"{sig.name} {version} {where}. {sig.summary}{cve}"

    @staticmethod
    def _fix(sig) -> str:
        return f"Upgrade {sig.name} to a current, supported release."
