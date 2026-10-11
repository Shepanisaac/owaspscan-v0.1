"""A03: reflected input that is not escaped for its HTML context (active, GET only).

The probe value is inert text (a random token followed by the characters " ' < >).
Nothing executes; we only look at how the page echoes those characters back.
"""
from __future__ import annotations

import re
import secrets

from ..models import Finding, Severity
from .base import Check, ScanContext, register

SPECIAL = "\"'<>"
SNIPPET_PAD = 25


def _raw_in_js(text: str, start: int, chars: str) -> bool:
    """True if one of chars appears in the echoed characters without a preceding backslash."""
    for offset, char in enumerate(text[start:start + len(SPECIAL)]):
        if char in chars and text[start + offset - 1] != "\\":
            return True
    return False


def find_unescaped_context(text: str, prefix: str) -> tuple[str, int] | None:
    """Return (context label, index) for the first dangerous reflection of prefix, else None."""
    for match in re.finditer(re.escape(prefix), text):
        index = match.start()
        start = index + len(prefix)
        returned = text[start:start + len(SPECIAL)]
        before = text[:index]
        lowered = before.lower()

        if before.rfind("<!--") > before.rfind("-->"):
            continue  # inside an HTML comment: not executable
        script = lowered.rfind("<script")
        if script != -1 and script > lowered.rfind("</script") and ">" in before[script:]:
            if _raw_in_js(text, start, "\"'"):
                return "script block", index
            continue
        style = lowered.rfind("<style")
        if style != -1 and style > lowered.rfind("</style"):
            continue  # CSS context: out of scope for this check

        lt, gt = before.rfind("<"), before.rfind(">")
        if lt > gt and text[lt + 1:lt + 2].isalpha():  # inside an opening tag
            segment = before[lt:]
            quotes = list(re.finditer(r"=\s*([\"'])", segment))
            quote = quotes[-1].group(1) if quotes else None
            if quote and quote not in segment[quotes[-1].end():]:
                if quote in returned:
                    return "attribute value", index
            elif ">" in returned:
                return "HTML tag", index
            continue

        if "<" in returned and ">" in returned:
            return "HTML body", index
    return None


@register
class ReflectionCheck(Check):
    id = "reflection"
    category = "A03"
    description = "Reflected input not escaped for its context (possible XSS)"
    active = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for point in ctx.injection_points:
            prefix = "ows" + secrets.token_hex(4)
            response = ctx.probe(point.url, params=point.request_params(prefix + SPECIAL))
            if response is None:
                if ctx.probes_used >= ctx.config.max_probes:
                    break  # probe budget spent
                continue
            if "html" not in response.headers.get("content-type", ""):
                continue  # JSON / plain text echoes are not an XSS risk
            hit = find_unescaped_context(response.text, prefix)
            if hit is None:
                continue
            context, index = hit
            snippet = response.text[max(0, index - SNIPPET_PAD):
                                    index + len(prefix) + len(SPECIAL) + SNIPPET_PAD]
            snippet = " ".join(snippet.split())[:120].replace(prefix, "<token>")
            findings.append(self.finding(
                f"Unescaped reflected input in {context} (parameter '{point.param}')",
                Severity.MEDIUM, point.url,
                f"Test characters came back unescaped. Response excerpt: {snippet}",
                "HTML-encode output for the right context (body, attribute, JavaScript), "
                "use a templating engine with auto-escaping, and add a Content-Security-Policy."))
        return findings
