import httpx

from conftest import HTML
from owaspscan.checks.base import REGISTRY
from owaspscan.checks.host_header import TEST_HOST, HostHeaderCheck
from owaspscan.models import Severity


def run(make_ctx, handler, target="https://example.test/"):
    ctx = make_ctx(handler, target)
    return HostHeaderCheck().run(ctx), ctx


def test_is_active_check():
    assert REGISTRY["host-header"].active is True


def test_clean_app_produces_no_findings(make_ctx):
    found, _ = run(make_ctx, lambda r: httpx.Response(200, headers=HTML, text="<p>ok</p>"))
    assert found == []


def test_host_header_reflected_in_page_flagged(make_ctx):
    def handler(request):
        host = request.headers.get("host", "")
        body = f'<link rel="canonical" href="https://{host}/">' if host == TEST_HOST else "<p>ok</p>"
        return httpx.Response(200, headers=HTML, text=body)
    found, _ = run(make_ctx, handler)
    titles = {f.title for f in found}
    assert any("Host header" in t and "reflected" in t for t in titles)
    assert all(f.severity == Severity.MEDIUM for f in found)


def test_x_forwarded_host_reflected_in_page_flagged(make_ctx):
    def handler(request):
        xfh = request.headers.get("x-forwarded-host", "")
        body = f'<a href="https://{xfh}/reset">reset</a>' if xfh == TEST_HOST else "<p>ok</p>"
        return httpx.Response(200, headers=HTML, text=body)
    found, _ = run(make_ctx, handler)
    titles = {f.title for f in found}
    assert any("X-Forwarded-Host" in t for t in titles)


def test_host_header_reflected_in_redirect_flagged(make_ctx):
    def handler(request):
        host = request.headers.get("host", "")
        if host == TEST_HOST:
            return httpx.Response(302, headers={**HTML, "Location": f"https://{host}/"})
        return httpx.Response(200, headers=HTML, text="<p>ok</p>")
    found, _ = run(make_ctx, handler)
    assert len(found) == 1 and "redirect" in found[0].title


def test_redirect_to_fixed_host_is_clean(make_ctx):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(302, headers={**HTML, "Location": "https://example.test/home"})
        return httpx.Response(200, headers=HTML, text="<p>home</p>")
    found, _ = run(make_ctx, handler)
    assert found == []


def test_both_techniques_tried(make_ctx):
    calls = []
    def handler(request):
        calls.append((request.headers.get("host", ""), request.headers.get("x-forwarded-host", "")))
        return httpx.Response(200, headers=HTML, text="<p>ok</p>")
    _, ctx = run(make_ctx, handler)
    assert ctx.probes_used == 2


def test_probe_cap_respected(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"))
    ctx.config.max_probes = 0
    HostHeaderCheck().run(ctx)
    assert ctx.probes_used == 0
