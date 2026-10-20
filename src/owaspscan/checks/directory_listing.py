"""A05: Apache/nginx-style autoindex directory listings found during the crawl.
Passive — reads what the crawler already fetched, sends no extra requests.

Only recognizes the standard autoindex output format (a "<title>Index of /...</title>"
or an "<h1>Index of ..." heading, usually alongside a "Parent Directory" link). A custom
or themed directory-listing page with different markup will not be recognized — that is a
detection gap, not a clean bill of health.
"""
from __future__ import annotations

import re

from ..models import Finding, Severity
from .base import Check, ScanContext, register

INDEX_OF = re.compile(r"<title>\s*Index of [^<]*</title>|<h1>\s*Index of ", re.IGNORECASE)
PARENT_DIRECTORY = re.compile(r"Parent Directory", re.IGNORECASE)


@register
class DirectoryListingCheck(Check):
    id = "directory-listing"
    category = "A05"
    description = "Directory listing (autoindex) exposed for a crawled path"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for page in ctx.pages:
            if not page.is_html:
                continue
            body = page.response.text[:4000]
            if not INDEX_OF.search(body):
                continue
            evidence = ("Response title/heading matches the standard autoindex format"
                        + (", with a 'Parent Directory' link." if PARENT_DIRECTORY.search(body)
                           else "."))
            findings.append(self.finding(
                "Directory listing enabled", Severity.MEDIUM, page.url, evidence,
                "Disable directory autoindexing at the server/vhost level (e.g. "
                "'Options -Indexes' on Apache, no 'autoindex on;' on nginx), and add an "
                "index file to any directory that must stay reachable."))
        return findings
