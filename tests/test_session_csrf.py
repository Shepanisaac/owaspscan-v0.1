import httpx

from conftest import HTML
from owaspscan.checks.base import REGISTRY
from owaspscan.checks.csrf import CsrfCheck
from owaspscan.checks.session import SessionCheck
from owaspscan.models import Severity


def titles(found):
    return {f.title for f in found}


# ---------- session ----------

def test_session_is_passive():
    assert REGISTRY["session"].active is False


def test_no_cookies_is_clean(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"))
    assert SessionCheck().run(ctx) == []


def test_short_session_cookie_flagged(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"))
    ctx.config.cookies["sessionid"] = "abc123"
    found = SessionCheck().run(ctx)
    assert len(found) == 1 and found[0].severity == Severity.MEDIUM


def test_numeric_session_cookie_flagged(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"))
    ctx.config.cookies["auth_token"] = "1" * 20
    assert len(SessionCheck().run(ctx)) == 1


def test_random_long_session_cookie_is_clean(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"))
    ctx.config.cookies["session"] = "k7Qp2mXz9LtR4vWn8sYd1Ae6Fb3Jc"
    assert SessionCheck().run(ctx) == []


def test_non_session_cookie_name_ignored(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"))
    ctx.config.cookies["theme"] = "dark"
    assert SessionCheck().run(ctx) == []


# ---------- csrf ----------

def test_csrf_is_passive():
    assert REGISTRY["csrf"].active is False


def test_post_form_no_token_is_flagged(make_ctx):
    page = '<form method="post" action="/account/delete"><input name="confirm"></form>'
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text=page))
    found = CsrfCheck().run(ctx)
    assert len(found) == 1 and found[0].severity == Severity.MEDIUM


def test_post_form_with_token_is_clean(make_ctx):
    page = ('<form method="post" action="/account/delete">'
            '<input name="csrf_token" value="xyz"></form>')
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text=page))
    assert CsrfCheck().run(ctx) == []


def test_non_state_changing_form_ignored(make_ctx):
    page = '<form method="post" action="/search"><input name="q"></form>'
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text=page))
    assert CsrfCheck().run(ctx) == []


def test_get_form_ignored(make_ctx):
    page = '<form method="get" action="/delete"><input name="id"></form>'
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text=page))
    assert CsrfCheck().run(ctx) == []


def test_samesite_cookie_lowers_severity(make_ctx):
    page = '<form method="post" action="/update"><input name="x"></form>'
    headers = [("content-type", "text/html"), ("set-cookie", "session=a; SameSite=Lax")]
    ctx = make_ctx(lambda r: httpx.Response(200, headers=headers, text=page))
    found = CsrfCheck().run(ctx)
    assert len(found) == 1 and found[0].severity == Severity.LOW


def test_duplicate_form_reported_once(make_ctx):
    page = ('<form method="post" action="/delete"><input name="id"></form>'
            '<a href="/other">x</a>')
    def handler(request):
        if request.url.path == "/other":
            form = '<form method="post" action="/delete"><input name="id"></form>'
            return httpx.Response(200, headers=HTML, text=form)
        return httpx.Response(200, headers=HTML, text=page)
    ctx = make_ctx(handler)
    assert len(CsrfCheck().run(ctx)) == 1


# ---------- session: bearer tokens / JWT ----------

def _b64url(data: dict) -> str:
    import base64
    import json
    raw = json.dumps(data).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_jwt(header: dict, payload: dict, signature: str = "sig") -> str:
    return f"{_b64url(header)}.{_b64url(payload)}.{signature}"


def test_no_headers_is_clean(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"))
    assert SessionCheck().run(ctx) == []


def test_non_authorization_header_ignored(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"),
                    headers={"X-Api-Key": "123"})
    assert SessionCheck().run(ctx) == []


def test_non_bearer_authorization_ignored(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"),
                    headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert SessionCheck().run(ctx) == []


def test_opaque_short_bearer_token_flagged(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"),
                    headers={"Authorization": "Bearer abc123"})
    found = SessionCheck().run(ctx)
    assert len(found) == 1 and "Bearer token" in found[0].title


def test_opaque_long_random_bearer_token_is_clean(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"),
                    headers={"Authorization": "Bearer k7Qp2mXz9LtR4vWn8sYd1Ae6Fb3Jc"})
    assert SessionCheck().run(ctx) == []


def test_jwt_alg_none_flagged_high(make_ctx):
    token = make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "1", "exp": 9999999999})
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"),
                    headers={"Authorization": f"Bearer {token}"})
    found = SessionCheck().run(ctx)
    assert len(found) == 1 and found[0].severity == Severity.HIGH
    assert "alg" in found[0].title.lower()


def test_jwt_missing_exp_flagged_medium(make_ctx):
    token = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1"})
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"),
                    headers={"Authorization": f"Bearer {token}"})
    found = SessionCheck().run(ctx)
    assert len(found) == 1 and found[0].severity == Severity.MEDIUM
    assert "expiration" in found[0].title.lower()


def test_well_formed_jwt_is_clean(make_ctx):
    token = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999})
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"),
                    headers={"Authorization": f"Bearer {token}"})
    assert SessionCheck().run(ctx) == []


def test_jwt_both_alg_none_and_no_exp_reports_both(make_ctx):
    token = make_jwt({"alg": "none"}, {"sub": "1"})
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"),
                    headers={"Authorization": f"Bearer {token}"})
    found = SessionCheck().run(ctx)
    assert {f.severity for f in found} == {Severity.HIGH, Severity.MEDIUM}


def test_malformed_jwt_like_string_falls_back_to_opaque_check(make_ctx):
    # three dot-separated parts, but not valid base64/JSON — must not crash, and since
    # it's long/non-numeric it should be treated as a fine opaque token
    token = "not.a.jwt-but-looks-kinda-like-one-with-dots-1234567890"
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"),
                    headers={"Authorization": f"Bearer {token}"})
    assert SessionCheck().run(ctx) == []
