import httpx

from conftest import HTML
from owaspscan.checks.access_control import AccessControlCheck
from owaspscan.checks.base import REGISTRY
from owaspscan.models import Severity


def test_is_active_check():
    assert REGISTRY["access-control"].active is True


def test_no_cookies_configured_is_a_noop(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>public</p>"))
    assert AccessControlCheck().run(ctx) == [] and ctx.probes_used == 0


def test_page_open_without_cookie_is_flagged(make_ctx):
    # same handler regardless of cookie presence: the linked page needs no auth
    # (the landing page itself is never flagged — see test_landing_page_itself_is_never_flagged)
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, headers=HTML, text="<a href='/dashboard'>d</a>")
        return httpx.Response(200, headers=HTML, text="<title>Dashboard</title>" + "x" * 200)
    ctx = make_ctx(handler, cookies={"session": "abc123def456"})
    found = AccessControlCheck().run(ctx)
    assert len(found) == 1 and found[0].severity == Severity.LOW
    assert ctx.probes_used == 1


def test_id_like_url_escalates_to_high(make_ctx):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, headers=HTML, text="<a href='/invoice/1042'>i</a>")
        return httpx.Response(200, headers=HTML, text="<title>Invoice</title>" + "x" * 200)
    ctx = make_ctx(handler, cookies={"session": "abc123def456"})
    found = AccessControlCheck().run(ctx)
    assert len(found) == 1 and found[0].severity == Severity.HIGH


def test_properly_protected_page_is_clean(make_ctx):
    def handler(request):
        if "cookie" in request.headers:
            return httpx.Response(200, headers=HTML, text="<title>Private</title>" + "x" * 300)
        return httpx.Response(302, headers={**HTML, "Location": "/login"}, text="")
    ctx = make_ctx(handler, cookies={"session": "abc123def456"})
    assert AccessControlCheck().run(ctx) == []


def test_different_content_is_clean(make_ctx):
    def handler(request):
        if "cookie" in request.headers:
            return httpx.Response(200, headers=HTML, text="<title>My Account</title>" + "y" * 500)
        return httpx.Response(200, headers=HTML, text="<title>Please Log In</title>" + "z" * 50)
    ctx = make_ctx(handler, cookies={"session": "abc123def456"})
    assert AccessControlCheck().run(ctx) == []


def test_excluded_url_skipped(make_ctx):
    body = "<title>x</title>" + "x" * 200
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text=body),
                    "https://example.test/logout", cookies={"session": "abc123def456"})
    found = AccessControlCheck().run(ctx)
    assert found == [] and ctx.probes_used == 0


def test_probe_cap_respected(make_ctx):
    body = "<title>x</title>" + "x" * 200
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text=body),
                    cookies={"session": "abc123def456"})
    ctx.config.max_probes = 0
    AccessControlCheck().run(ctx)
    assert ctx.probes_used == 0


def test_anonymous_request_sends_no_cookie_header(make_ctx):
    seen_cookie_headers = []
    def handler(request):
        seen_cookie_headers.append(request.headers.get("cookie"))
        if request.url.path == "/":
            return httpx.Response(200, headers=HTML, text="<a href='/dashboard'>d</a>")
        return httpx.Response(200, headers=HTML, text="<title>x</title>" + "x" * 200)
    ctx = make_ctx(handler, cookies={"session": "abc123def456"})
    AccessControlCheck().run(ctx)
    # requests are: landing (with cookie), /dashboard authenticated crawl (with cookie),
    # then the anonymous probe of /dashboard (must have no cookie)
    assert seen_cookie_headers[0] is not None
    assert seen_cookie_headers[-1] is None


def test_numeric_host_does_not_look_id_like(make_ctx):
    # the landing page is skipped anyway, but a linked page under a numeric-IP host
    # must not be escalated to HIGH just because the host contains digits
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, headers=HTML, text="<a href='/dashboard'>d</a>")
        return httpx.Response(200, headers=HTML, text="<title>Dash</title>" + "x" * 200)
    ctx = make_ctx(handler, "http://127.0.0.1:9999/", cookies={"session": "abc123def456"})
    found = AccessControlCheck().run(ctx)
    assert len(found) == 1 and found[0].severity == Severity.LOW


def test_landing_page_itself_is_never_flagged(make_ctx):
    body = "<title>Home</title>" + "x" * 200
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text=body),
                    cookies={"session": "abc123def456"})
    assert AccessControlCheck().run(ctx) == [] and ctx.probes_used == 0


def test_header_alone_also_triggers_the_check(make_ctx):
    # same scenario as test_page_open_without_cookie_is_flagged, but authenticated via
    # a bearer header instead of a cookie
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, headers=HTML, text="<a href='/dashboard'>d</a>")
        return httpx.Response(200, headers=HTML, text="<title>Dashboard</title>" + "x" * 200)
    ctx = make_ctx(handler, headers={"Authorization": "Bearer sometoken"})
    found = AccessControlCheck().run(ctx)
    assert len(found) == 1 and found[0].severity == Severity.LOW


def test_anonymous_request_sends_no_auth_header(make_ctx):
    seen_auth_headers = []
    def handler(request):
        seen_auth_headers.append(request.headers.get("authorization"))
        if request.url.path == "/":
            return httpx.Response(200, headers=HTML, text="<a href='/dashboard'>d</a>")
        return httpx.Response(200, headers=HTML, text="<title>x</title>" + "x" * 200)
    ctx = make_ctx(handler, headers={"Authorization": "Bearer sometoken"})
    AccessControlCheck().run(ctx)
    assert seen_auth_headers[0] is not None
    assert seen_auth_headers[-1] is None


def test_mostly_401_crawl_reports_stale_credentials_and_stops(make_ctx):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, headers=HTML, text="<a href='/a'>a</a><a href='/b'>b</a>")
        return httpx.Response(401, headers=HTML, text="unauthorized")
    ctx = make_ctx(handler, cookies={"session": "abc123def456"})
    found = AccessControlCheck().run(ctx)
    assert len(found) == 1 and found[0].severity == Severity.INFO
    assert "invalid or expired" in found[0].title
    assert ctx.probes_used == 0  # the comparison loop never ran


def test_mostly_ok_crawl_with_one_401_still_runs_normally(make_ctx):
    # under the 50% threshold: a single stale link shouldn't suppress real findings
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, headers=HTML,
                                  text="<a href='/a'>a</a><a href='/b'>b</a><a href='/c'>c</a>")
        if request.url.path == "/a":
            return httpx.Response(401, headers=HTML, text="unauthorized")
        return httpx.Response(200, headers=HTML, text="<title>x</title>" + "x" * 200)
    ctx = make_ctx(handler, cookies={"session": "abc123def456"})
    found = AccessControlCheck().run(ctx)
    # the real access-control findings on /b and /c must still appear — no stale-credential
    # finding should have suppressed them
    assert not any("invalid or expired" in f.title for f in found)
    assert len(found) == 2
