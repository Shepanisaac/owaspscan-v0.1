"""A01: path traversal / local file inclusion via a parameter that looks like it names a
file or path (active, GET only). Like crlf-injection, this is a confirmed finding, not a
heuristic: the marker content checked for (a line from /etc/passwd, a section header from
win.ini) can only appear in the response if the traversal payload actually reached outside
the intended directory and the file was read back — there's no other plausible way for it
to show up.
"""
from __future__ import annotations

import re

from ..models import Finding, Severity
from .base import Check, ScanContext, register

NAME_HINTS = (
    "file", "path", "dir", "folder", "page", "doc", "document", "template",
    "include", "load", "filename", "attachment", "download",
)

# (label, payload, marker pattern). One payload per OS family keeps probe cost bounded at
# 2 requests per candidate parameter; depth of 8 clears most realistic install layouts.
PAYLOADS = (
    ("Unix /etc/passwd", "../" * 8 + "etc/passwd", re.compile(r"root:[^:\n]*:0:0:")),
    ("Windows win.ini", "..\\" * 8 + "windows\\win.ini", re.compile(r"\[fonts\]", re.IGNORECASE)),
)


def _looks_file_like(name: str) -> bool:
    lowered = re.sub(r"[^a-z]", "", name.lower())
    return any(hint in lowered for hint in NAME_HINTS)


@register
class PathTraversalCheck(Check):
    id = "path-traversal"
    category = "A01"
    description = "Path traversal / local file inclusion via a file- or path-shaped parameter"
    active = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for point in ctx.injection_points:
            if not _looks_file_like(point.param):
                continue
            for label, payload, marker in PAYLOADS:
                response = ctx.probe(point.url, params=point.request_params(payload))
                if response is None:
                    if ctx.probes_used >= ctx.config.max_probes:
                        return findings
                    continue
                if self._reads_as_text(response) and marker.search(response.text[:50_000]):
                    findings.append(self.finding(
                        f"Path traversal via parameter '{point.param}' ({label})",
                        Severity.HIGH, point.url,
                        f"Setting {point.param} to a traversal sequence targeting {label} "
                        "produced a response containing that file's distinctive content — "
                        "the server read a file outside the directory this parameter was "
                        "meant to stay inside.",
                        "Never build a filesystem path from user input directly. Resolve "
                        "the final path and verify it stays inside an allow-listed base "
                        "directory, or map the parameter to a fixed set of known-safe "
                        "files/IDs instead of a raw path."))
                    break  # this parameter is confirmed; no need to try the other OS payload
        return findings

    @staticmethod
    def _reads_as_text(response) -> bool:
        kind = response.headers.get("content-type", "").lower()
        if not kind:
            return True  # no declared type: still worth scanning, most servers default to text
        return any(token in kind for token in ("text/", "json", "xml"))
