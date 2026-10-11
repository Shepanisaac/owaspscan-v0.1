import httpx

from conftest import HTML
from owaspscan.checks.base import REGISTRY
from owaspscan.checks.open_redirect import TEST_URL, OpenRedirectCheck, _looks_redirect_like
from owaspscan.models import Severity

TARGET = "https://example.test/login?next=/dashboard"


def http_redirect_app(param="next", to=None):
    """Redirects to the parameter's value when it looks absolute (http(s):// or //),
    which is what real apps that are vulnerable do. A relative value like the initial
    crawl's own "/dashboard" is left alone, so crawling the target page doesn't itself
    trigger a redirect. `to`, if given, overrides with a fixed destination instead."""
    def handler(request):
        value = request.url.params.get(param, "")
        if to is not None:
            return httpx.Response(302, headers={**HTML, "Location": to})
        if value.startswith(("http://", "https://", "//")):
            return httpx.Response(302, headers={**HTML, "Location": value})
        return httpx.Response(200, headers=HTML, text="<p>login</p>")
    return handler


def run(make_ctx, handler, target=TARGET):
    ctx = make_ctx(handler, target)
    return OpenRedirectCheck().run(ctx), ctx


def test_is_active_check():
    assert REGISTRY["open-redirect"].active is True


def test_name_matcher():
    for name in ("next", "returnUrl", "redirect_uri", "dest", "go", "callback"):
        assert _looks_redirect_like(name)
    for name in ("id", "q", "page", "username"):
        assert not _looks_redirect_like(name)


def test_external_redirect_is_flagged(make_ctx):
    found, _ = run(make_ctx, http_redirect_app())
    assert len(found) == 1 and found[0].severity == Severity.MEDIUM
    assert "'next'" in found[0].title


def test_relative_redirect_target_is_clean(make_ctx):
    # app always redirects to a fixed relative path, ignoring the parameter: safe
    found, _ = run(make_ctx, http_redirect_app(to="/dashboard"))
    assert found == []


def test_same_host_redirect_is_clean(make_ctx):
    found, _ = run(make_ctx, http_redirect_app(to="https://example.test/ok"))
    assert found == []


def test_non_redirect_param_is_never_probed(make_ctx):
    found, ctx = run(make_ctx, http_redirect_app(param="id"), "https://example.test/item?id=5")
    assert found == [] and ctx.probes_used == 0


def test_meta_refresh_redirect_is_flagged_as_low(make_ctx):
    def handler(request):
        value = request.url.params.get("next", "")
        body = f'<meta http-equiv="refresh" content="0;url={value}">' if value else "<p>x</p>"
        return httpx.Response(200, headers=HTML, text=body)
    found, _ = run(make_ctx, handler)
    assert len(found) == 1 and found[0].severity == Severity.LOW
    assert "meta refresh" in found[0].evidence


def test_js_redirect_is_flagged(make_ctx):
    def handler(request):
        value = request.url.params.get("next", "")
        body = f'<script>window.location.href = "{value}";</script>' if value else "<p>x</p>"
        return httpx.Response(200, headers=HTML, text=body)
    found, _ = run(make_ctx, handler)
    assert len(found) == 1 and "JavaScript" in found[0].evidence


def test_two_candidate_params_both_tested(make_ctx):
    def handler(request):
        q = request.url.params
        # each param independently redirects to its OWN value when that value is absolute
        for name in ("next", "returnUrl"):
            value = q.get(name, "")
            if value.startswith(("http://", "https://", "//")):
                return httpx.Response(302, headers={**HTML, "Location": value})
        return httpx.Response(200, headers=HTML, text="<p>x</p>")
    found, ctx = run(make_ctx, handler, "https://example.test/login?next=/a&returnUrl=/b")
    assert len(found) == 2 and ctx.probes_used == 2


def test_probe_cap_respected(make_ctx):
    ctx = make_ctx(http_redirect_app(), TARGET)
    ctx.config.max_probes = 0
    OpenRedirectCheck().run(ctx)
    assert ctx.probes_used == 0


def test_get_form_field_is_tested(make_ctx):
    def handler(request):
        value = request.url.params.get("redirectTo", "")
        if request.url.path == "/go" and value:
            return httpx.Response(302, headers={**HTML, "Location": value})
        form = '<form action="/go"><input name="redirectTo" value="/home"></form>'
        return httpx.Response(200, headers=HTML, text=form)
    found, _ = run(make_ctx, handler, "https://example.test/")
    assert len(found) == 1 and "redirectTo" in found[0].title


def test_probe_response_uses_follow_redirects_false(make_ctx):
    # the transport sees the raw redirect request; httpx must not chase it itself
    seen = []
    def handler(request):
        seen.append(str(request.url))
        if TEST_URL.rstrip("/") in request.url.params.get("next", ""):
            return httpx.Response(302, headers={**HTML, "Location": TEST_URL})
        return httpx.Response(200, headers=HTML, text="<p>x</p>")
    found, _ = run(make_ctx, handler)
    assert len(found) == 1
    assert all("evil" not in u and "redirect-test.invalid" not in u.split("?")[0] for u in seen[1:])
