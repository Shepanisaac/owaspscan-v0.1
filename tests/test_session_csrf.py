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
