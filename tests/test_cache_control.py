import httpx

from conftest import HTML
from owaspscan.checks.base import REGISTRY
from owaspscan.checks.cache_control import CacheControlCheck
from owaspscan.models import Severity


def page(body, headers=None):
    return lambda request: httpx.Response(200, headers={**HTML, **(headers or {})}, text=body)


def test_is_passive():
    assert REGISTRY["cache-control"].active is False


def test_login_page_no_cache_control_flagged(make_ctx):
    body = '<form><input type="password" name="pw"></form>'
    ctx = make_ctx(page(body))
    found = CacheControlCheck().run(ctx)
    assert len(found) == 1 and found[0].severity == Severity.MEDIUM


def test_login_page_with_no_store_is_clean(make_ctx):
    body = '<form><input type="password" name="pw"></form>'
    ctx = make_ctx(page(body, {"Cache-Control": "no-store"}))
    assert CacheControlCheck().run(ctx) == []


def test_login_page_with_other_cache_control_still_flagged(make_ctx):
    body = '<form><input type="password" name="pw"></form>'
    ctx = make_ctx(page(body, {"Cache-Control": "private, max-age=0"}))
    found = CacheControlCheck().run(ctx)
    assert len(found) == 1


def test_non_login_page_never_flagged(make_ctx):
    body = '<form><input type="text" name="q"></form>'
    ctx = make_ctx(page(body))
    assert CacheControlCheck().run(ctx) == []


def test_page_with_no_form_never_flagged(make_ctx):
    ctx = make_ctx(page("<p>hello</p>"))
    assert CacheControlCheck().run(ctx) == []
