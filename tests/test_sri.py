import httpx

from conftest import HTML
from owaspscan.checks.base import REGISTRY
from owaspscan.checks.sri import SRICheck
from owaspscan.models import Severity


def page(body):
    return lambda request: httpx.Response(200, headers=HTML, text=body)


def test_is_passive():
    assert REGISTRY["sri"].active is False


def test_cross_origin_script_no_integrity_flagged(make_ctx):
    body = '<script src="https://cdn.example.net/lib.js"></script>'
    ctx = make_ctx(page(body))
    found = SRICheck().run(ctx)
    assert len(found) == 1
    assert found[0].severity == Severity.MEDIUM
    assert "no Subresource Integrity" in found[0].title


def test_cross_origin_script_with_full_sri_is_clean(make_ctx):
    body = ('<script src="https://cdn.example.net/lib.js" '
            'integrity="sha384-abc123" crossorigin="anonymous"></script>')
    ctx = make_ctx(page(body))
    assert SRICheck().run(ctx) == []


def test_integrity_without_crossorigin_flagged_low(make_ctx):
    body = '<script src="https://cdn.example.net/lib.js" integrity="sha384-abc123"></script>'
    ctx = make_ctx(page(body))
    found = SRICheck().run(ctx)
    assert len(found) == 1 and found[0].severity == Severity.LOW
    assert "no crossorigin" in found[0].title


def test_same_origin_script_never_flagged(make_ctx):
    body = '<script src="/js/app.js"></script>'
    ctx = make_ctx(page(body))
    assert SRICheck().run(ctx) == []


def test_cross_origin_stylesheet_no_integrity_flagged(make_ctx):
    body = '<link rel="stylesheet" href="https://cdn.example.net/style.css">'
    ctx = make_ctx(page(body))
    found = SRICheck().run(ctx)
    assert len(found) == 1 and "link" in found[0].title


def test_non_stylesheet_link_ignored(make_ctx):
    body = '<link rel="icon" href="https://cdn.example.net/favicon.ico">'
    ctx = make_ctx(page(body))
    assert SRICheck().run(ctx) == []


def test_data_uri_script_ignored(make_ctx):
    body = '<script src="data:text/javascript;base64,YWxlcnQoMSk="></script>'
    ctx = make_ctx(page(body))
    assert SRICheck().run(ctx) == []


def test_duplicate_cross_origin_script_deduped(make_ctx):
    body = ('<script src="https://cdn.example.net/lib.js"></script>'
            '<script src="https://cdn.example.net/lib.js"></script>')
    ctx = make_ctx(page(body))
    assert len(SRICheck().run(ctx)) == 1


def test_no_script_or_link_tags_is_clean(make_ctx):
    ctx = make_ctx(page("<p>hello</p>"))
    assert SRICheck().run(ctx) == []
