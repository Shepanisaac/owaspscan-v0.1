"""A03: server-side template injection (active, GET only). Like crlf-injection and
path-traversal, this is a confirmed finding, not a heuristic: the payload asks the
template engine to multiply two numbers, and the computed product appearing in the
response — with the template syntax itself gone — can only happen if a template engine
actually evaluated the expression server-side. There's no other plausible explanation.

The two operands are generated fresh per probe so the expected result isn't a fixed,
guessable number that could coincidentally already appear on the page.
"""
from __future__ import annotations

import re
import secrets

from ..models import Finding, Severity
from .base import Check, ScanContext, register

# {a} and {b} are substituted with the random operands; {product} with their product.
# Covers the syntaxes of the most common template engines without trying every engine
# individually — Jinja2/Twig/Nunjucks share {{ }}, Freemarker/JSP EL share ${ }, ERB uses
# <%= %>.
PAYLOAD_TEMPLATES = (
    ("Jinja2/Twig-style", "{{{{{a}*{b}}}}}"),
    ("Freemarker/EL-style", "${{{a}*{b}}}"),
    ("ERB-style", "<%= {a}*{b} %>"),
)


def _random_operands() -> tuple[int, int]:
    # Small-ish distinct primes: large enough that their product is unlikely to already
    # appear on an ordinary page, small enough the product stays a short, readable number.
    primes = (7, 11, 13, 17, 19, 23, 29, 31)
    a, b = secrets.choice(primes), secrets.choice(primes)
    while b == a:
        b = secrets.choice(primes)
    return a, b


@register
class SSTICheck(Check):
    id = "ssti"
    category = "A03"
    description = "Server-side template injection (payload arithmetic evaluated by the server)"
    active = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for point in ctx.injection_points:
            a, b = _random_operands()
            product = a * b
            marker = re.compile(rf"(?<!\d){product}(?!\d)")

            for label, template in PAYLOAD_TEMPLATES:
                payload = template.format(a=a, b=b)
                response = ctx.probe(point.url, params=point.request_params(payload))
                if response is None:
                    if ctx.probes_used >= ctx.config.max_probes:
                        return findings
                    continue
                if "html" not in response.headers.get("content-type", "") and \
                   "text" not in response.headers.get("content-type", ""):
                    break  # non-text response: not worth trying the other syntaxes either
                text = response.text[:50_000]
                if payload not in text and marker.search(text):
                    findings.append(self.finding(
                        f"Possible server-side template injection in parameter "
                        f"'{point.param}' ({label})", Severity.HIGH, point.url,
                        f"Setting {point.param} to '{payload}' produced a response "
                        f"containing {product} (the product of {a} and {b}) with no trace "
                        "of the template syntax itself — the server evaluated the "
                        "expression rather than treating it as plain text.",
                        "Never pass user input into a template's render/compile step. "
                        "Treat it strictly as data (pass it as a template variable, not as "
                        "part of the template source), and use a sandboxed or logic-less "
                        "template engine if user input must influence rendering."))
                    break  # confirmed; no need to try the other syntaxes for this parameter
        return findings
