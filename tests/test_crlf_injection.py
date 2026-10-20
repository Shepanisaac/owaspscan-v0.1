import httpx

from conftest import HTML
from owaspscan.checks.base import REGISTRY
from owaspscan.checks.crlf_injection import CrlfInjectionCheck

TARGET = "https://example.test/search?q=hello"


def run(make_ctx, handler, target=TARGET):
    ctx = make_ctx(handler, target)
    return CrlfInjectionCheck().run(ctx), ctx


def test_is_active_check():
    assert REGISTRY["crlf-injection"].active is True


def test_clean_app_produces_no_findings(make_ctx):
    found, _ = run(make_ctx, lambda r: httpx.Response(200, headers=HTML, text="<p>ok</p>"))
    assert found == []


def test_vulnerable_app_flagged_high(make_ctx):
    # simulates a server that naively builds a header from the raw (decoded) parameter value
    def handler(request):
        value = request.url.params.get("q", "")
        headers = dict(HTML)
        if "\r\n" in value or "X-Owaspscan-Crlf-Test" in value:
            headers["X-Owaspscan-Crlf-Test"] = "injected"
        return httpx.Response(200, headers=headers, text="<p>ok</p>")
    found, ctx = run(make_ctx, handler)
    assert len(found) == 1
    assert "crlf" in found[0].title.lower() or "response splitting" in found[0].title.lower()
    assert ctx.probes_used == 1


def test_marker_header_check_is_case_insensitive(make_ctx):
    def handler(request):
        return httpx.Response(200, headers={**HTML, "x-owaspscan-crlf-test": "injected"},
                               text="<p>ok</p>")
    found, _ = run(make_ctx, handler)
    assert len(found) == 1


def test_probe_cap_respected(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>ok</p>"), TARGET)
    ctx.config.max_probes = 0
    CrlfInjectionCheck().run(ctx)
    assert ctx.probes_used == 0


def test_multiple_params_each_tested(make_ctx):
    def handler(request):
        return httpx.Response(200, headers=HTML, text="<p>ok</p>")
    found, ctx = run(make_ctx, handler, "https://example.test/search?q=hello&page=1")
    assert found == [] and ctx.probes_used == 2
