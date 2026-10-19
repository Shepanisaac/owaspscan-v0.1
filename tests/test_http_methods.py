import httpx

from conftest import HTML
from owaspscan.checks.base import REGISTRY
from owaspscan.checks.http_methods import HttpMethodsCheck
from owaspscan.models import Severity


def run(make_ctx, handler, target="https://example.test/"):
    ctx = make_ctx(handler, target)
    return HttpMethodsCheck().run(ctx), ctx


def test_is_active_check():
    assert REGISTRY["http-methods"].active is True


def test_clean_server_produces_no_findings(make_ctx):
    def handler(request):
        if request.method == "OPTIONS":
            return httpx.Response(204, headers={"Allow": "GET, HEAD, OPTIONS"})
        if request.method == "TRACE":
            return httpx.Response(405, headers=HTML, text="Method Not Allowed")
        return httpx.Response(200, headers=HTML, text="<p>x</p>")
    found, _ = run(make_ctx, handler)
    assert found == []


def test_trace_enabled_flagged_medium(make_ctx):
    def handler(request):
        if request.method == "TRACE":
            return httpx.Response(200, headers=HTML, text="TRACE echo")
        if request.method == "OPTIONS":
            return httpx.Response(204, headers={"Allow": "GET, HEAD, OPTIONS, TRACE"})
        return httpx.Response(200, headers=HTML, text="<p>x</p>")
    found, _ = run(make_ctx, handler)
    titles = {f.title for f in found}
    assert "TRACE method is enabled" in titles
    trace_finding = next(f for f in found if f.title == "TRACE method is enabled")
    assert trace_finding.severity == Severity.MEDIUM


def test_trace_rejected_with_non_200_is_clean(make_ctx):
    def handler(request):
        if request.method == "TRACE":
            return httpx.Response(501, headers=HTML, text="Not Implemented")
        return httpx.Response(200, headers=HTML, text="<p>x</p>")
    found, _ = run(make_ctx, handler)
    assert "TRACE method is enabled" not in {f.title for f in found}


def test_options_advertises_dangerous_methods_flagged_low(make_ctx):
    def handler(request):
        if request.method == "OPTIONS":
            return httpx.Response(204, headers={"Allow": "GET, HEAD, OPTIONS, PUT, DELETE"})
        if request.method == "TRACE":
            return httpx.Response(405, headers=HTML, text="x")
        return httpx.Response(200, headers=HTML, text="<p>x</p>")
    found, _ = run(make_ctx, handler)
    assert len(found) == 1
    assert found[0].severity == Severity.LOW
    assert "PUT" in found[0].title and "DELETE" in found[0].title


def test_options_with_only_safe_methods_is_clean(make_ctx):
    def handler(request):
        if request.method == "OPTIONS":
            return httpx.Response(204, headers={"Allow": "GET, HEAD, POST, OPTIONS"})
        if request.method == "TRACE":
            return httpx.Response(405, headers=HTML, text="x")
        return httpx.Response(200, headers=HTML, text="<p>x</p>")
    found, _ = run(make_ctx, handler)
    assert found == []


def test_cors_allow_methods_header_also_checked(make_ctx):
    def handler(request):
        if request.method == "OPTIONS":
            return httpx.Response(204, headers={"Access-Control-Allow-Methods": "GET, CONNECT"})
        if request.method == "TRACE":
            return httpx.Response(405, headers=HTML, text="x")
        return httpx.Response(200, headers=HTML, text="<p>x</p>")
    found, _ = run(make_ctx, handler)
    assert len(found) == 1 and "CONNECT" in found[0].title


def test_only_landing_page_is_tested(make_ctx):
    requested = []
    def handler(request):
        requested.append((request.method, str(request.url)))
        if request.url.path == "/":
            return httpx.Response(200, headers=HTML, text='<a href="/other">x</a>')
        return httpx.Response(200, headers=HTML, text="<p>other</p>")
    run(make_ctx, handler)
    methods_on_other = [m for m, u in requested if "/other" in u and m in ("OPTIONS", "TRACE")]
    assert methods_on_other == []


def test_probe_cap_respected(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"))
    ctx.config.max_probes = 0
    HttpMethodsCheck().run(ctx)
    assert ctx.probes_used == 0
