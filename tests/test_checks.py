import httpx

from conftest import HTML
from owaspscan.checks.cookies import CookieCheck
from owaspscan.checks.disclosure import DisclosureCheck
from owaspscan.checks.exposed_files import ExposedFilesCheck
from owaspscan.checks.headers import SecurityHeadersCheck
from owaspscan.checks.transport import TransportCheck
from owaspscan.models import Severity


def titles(findings):
    return {f.title for f in findings}


def test_headers_missing(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<html></html>"))
    found = titles(SecurityHeadersCheck().run(ctx))
    assert "Missing Content-Security-Policy header" in found
    assert "Missing Strict-Transport-Security header" in found
    assert "No clickjacking protection" in found


def test_headers_present(make_ctx):
    good = {**HTML, "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
            "Strict-Transport-Security": "max-age=31536000"}
    ctx = make_ctx(lambda r: httpx.Response(200, headers=good, text="<html></html>"))
    assert SecurityHeadersCheck().run(ctx) == []


def test_cookie_flags(make_ctx):
    headers = [("content-type", "text/html"), ("set-cookie", "sessionid=abc; Path=/")]
    ctx = make_ctx(lambda r: httpx.Response(200, headers=headers, text="x"))
    found = CookieCheck().run(ctx)
    assert {"Cookie 'sessionid' missing Secure flag",
            "Cookie 'sessionid' missing HttpOnly flag",
            "Cookie 'sessionid' missing SameSite attribute"} == titles(found)
    assert max(f.severity for f in found) == Severity.MEDIUM


def test_cookie_secure_ok(make_ctx):
    cookie = "sessionid=abc; Secure; HttpOnly; SameSite=Lax"
    headers = [("content-type", "text/html"), ("set-cookie", cookie)]
    ctx = make_ctx(lambda r: httpx.Response(200, headers=headers, text="x"))
    assert CookieCheck().run(ctx) == []


def test_disclosure(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers={**HTML, "Server": "nginx/1.18.0"}, text="x"))
    findings = DisclosureCheck().run(ctx)
    assert len(findings) == 1 and findings[0].severity == Severity.LOW


def test_transport_http_flagged(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="x"), "http://example.test/")
    assert len(TransportCheck().run(ctx)) == 1


def test_transport_https_ok(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="x"))
    assert TransportCheck().run(ctx) == []


def test_exposed_git(make_ctx):
    def handler(request):
        if request.url.path == "/.git/HEAD":
            return httpx.Response(200, headers={"content-type": "text/plain"},
                                  text="ref: refs/heads/main\n")
        return httpx.Response(404, headers=HTML, text="nope")
    findings = ExposedFilesCheck().run(make_ctx(handler))
    assert titles(findings) == {"Git repository exposed"}


def test_exposed_files_ignores_spa_fallback(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="FOO=bar\nPHP Version"))
    assert [f.title for f in ExposedFilesCheck().run(ctx)] == ["phpinfo page exposed"]
