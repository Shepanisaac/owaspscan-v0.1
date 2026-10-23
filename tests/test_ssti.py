import re

import httpx

from conftest import HTML
from owaspscan.checks.base import REGISTRY
from owaspscan.checks.ssti import SSTICheck
from owaspscan.models import Severity

TARGET = "https://example.test/greet?name=guest"


def run(make_ctx, handler, target=TARGET):
    ctx = make_ctx(handler, target)
    return SSTICheck().run(ctx), ctx


def test_is_active_check():
    assert REGISTRY["ssti"].active is True


def test_clean_app_produces_no_findings(make_ctx):
    found, _ = run(make_ctx, lambda r: httpx.Response(200, headers=HTML, text="<p>hi guest</p>"))
    assert found == []


def test_jinja2_style_evaluation_flagged_high(make_ctx):
    def handler(request):
        value = request.url.params.get("name", "")
        match = re.search(r"\{\{(\d+)\*(\d+)\}\}", value)
        if match:
            product = int(match.group(1)) * int(match.group(2))
            return httpx.Response(200, headers=HTML, text=f"<p>hi {product}</p>")
        return httpx.Response(200, headers=HTML, text=f"<p>hi {value}</p>")
    found, _ = run(make_ctx, handler)
    assert len(found) == 1
    assert found[0].severity == Severity.HIGH
    assert "Jinja2" in found[0].title


def test_freemarker_style_evaluation_flagged(make_ctx):
    def handler(request):
        value = request.url.params.get("name", "")
        match = re.search(r"\$\{(\d+)\*(\d+)\}", value)
        if match:
            product = int(match.group(1)) * int(match.group(2))
            return httpx.Response(200, headers=HTML, text=f"<p>hi {product}</p>")
        return httpx.Response(200, headers=HTML, text=f"<p>hi {value}</p>")
    found, _ = run(make_ctx, handler)
    assert len(found) == 1 and "Freemarker" in found[0].title


def test_reflected_payload_verbatim_is_clean(make_ctx):
    # app just echoes the raw input back (no template evaluation at all)
    def handler(request):
        value = request.url.params.get("name", "")
        return httpx.Response(200, headers=HTML, text=f"<p>hi {value}</p>")
    found, _ = run(make_ctx, handler)
    assert found == []


def test_coincidental_number_without_template_syntax_removed_is_clean(make_ctx):
    # the product number could theoretically appear on an ordinary page; since the raw
    # payload (with template syntax) is ALSO present, this must not be flagged
    def handler(request):
        value = request.url.params.get("name", "")
        return httpx.Response(200, headers=HTML, text=f"<p>query was: {value}</p>")
    found, _ = run(make_ctx, handler)
    assert found == []


def test_stops_after_first_confirmed_syntax(make_ctx):
    calls = []
    def handler(request):
        value = request.url.params.get("name", "")
        calls.append(value)
        match = re.search(r"\{\{(\d+)\*(\d+)\}\}", value)
        if match:
            product = int(match.group(1)) * int(match.group(2))
            return httpx.Response(200, headers=HTML, text=f"<p>hi {product}</p>")
        return httpx.Response(200, headers=HTML, text="<p>hi</p>")
    found, ctx = run(make_ctx, handler)
    assert len(found) == 1 and ctx.probes_used == 1  # other two syntaxes never tried


def test_non_text_response_skipped(make_ctx):
    def handler(request):
        return httpx.Response(200, headers={"content-type": "application/octet-stream"},
                               text="1337")
    found, ctx = run(make_ctx, handler)
    assert found == [] and ctx.probes_used == 1  # breaks after the first non-text response


def test_probe_cap_respected(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>hi</p>"), TARGET)
    ctx.config.max_probes = 0
    SSTICheck().run(ctx)
    assert ctx.probes_used == 0
