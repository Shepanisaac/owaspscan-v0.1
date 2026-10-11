import html

import httpx

from conftest import HTML
from owaspscan.checks.base import REGISTRY
from owaspscan.checks.reflection import ReflectionCheck, find_unescaped_context
from owaspscan.models import Severity

TARGET = "https://example.test/search?q=hello"


def echo_handler(template, transform=lambda s: s, content_type=HTML):
    """Serve a page whose template contains {q}, filled from the 'q' query parameter."""
    def handler(request):
        q = request.url.params.get("q", "")
        return httpx.Response(200, headers=content_type, text=template.format(q=transform(q)))
    return handler


def run(make_ctx, handler):
    return ReflectionCheck().run(make_ctx(handler, TARGET))


def js_escape(s):
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'")


def test_is_active_check():
    assert REGISTRY["reflection"].active is True


def test_body_unescaped_is_flagged(make_ctx):
    found = run(make_ctx, echo_handler("<p>You searched: {q}</p>"))
    assert len(found) == 1 and found[0].severity == Severity.MEDIUM
    assert "HTML body" in found[0].title and "'q'" in found[0].title


def test_body_escaped_is_clean(make_ctx):
    assert run(make_ctx, echo_handler("<p>{q}</p>", html.escape)) == []


def test_body_quotes_raw_but_brackets_escaped_is_clean(make_ctx):
    # quotes are harmless in an HTML body, so this must not be a false positive
    assert run(make_ctx, echo_handler("<p>{q}</p>", lambda s: html.escape(s, quote=False))) == []


def test_attribute_unescaped_is_flagged(make_ctx):
    found = run(make_ctx, echo_handler('<input value="{q}">'))
    assert len(found) == 1 and "attribute value" in found[0].title


def test_attribute_fully_escaped_is_clean(make_ctx):
    assert run(make_ctx, echo_handler('<input value="{q}">', html.escape)) == []


def test_attribute_only_other_quote_raw_is_clean(make_ctx):
    # double-quoted attribute: a raw single quote cannot break out of it
    def transform(s):
        return s.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")
    assert run(make_ctx, echo_handler('<input value="{q}">', transform)) == []


def test_script_unescaped_is_flagged(make_ctx):
    found = run(make_ctx, echo_handler('<script>var s = "{q}";</script>'))
    assert len(found) == 1 and "script block" in found[0].title


def test_script_escaped_is_clean(make_ctx):
    assert run(make_ctx, echo_handler('<script>var s = "{q}";</script>', js_escape)) == []


def test_comment_reflection_is_ignored(make_ctx):
    assert run(make_ctx, echo_handler("<p>ok</p><!-- {q} -->")) == []


def test_json_response_is_ignored(make_ctx):
    handler = echo_handler('{{"q": "{q}"}}', content_type={"content-type": "application/json"})
    assert run(make_ctx, handler) == []


def test_not_reflected_is_clean(make_ctx):
    assert run(make_ctx, echo_handler("<p>static page {q}</p>", lambda s: "fixed")) == []


def test_post_forms_are_never_probed(make_ctx):
    page = '<form method="post" action="/login"><input name="user"></form>'
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text=page))
    assert ReflectionCheck().run(ctx) == [] and ctx.probes_used == 0


def test_get_form_fields_are_probed(make_ctx):
    def handler(request):
        term = request.url.params.get("term", "")
        page = f'<form action="/find"><input name="term"></form><p>{term}</p>'
        return httpx.Response(200, headers=HTML, text=page)
    found = ReflectionCheck().run(make_ctx(handler))
    assert any("'term'" in f.title for f in found)


def test_probe_cap_is_respected(make_ctx):
    page = '<a href="/x?a=1&b=2&c=3">x</a>'
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text=page), "https://example.test/x?a=1&b=2&c=3")
    ctx.config.max_probes = 1
    ReflectionCheck().run(ctx)
    assert ctx.probes_used == 1


def test_classifier_directly():
    assert find_unescaped_context('<p>tok"\'<></p>', "tok")[0] == "HTML body"
    assert find_unescaped_context("<p>tok&quot;&#x27;&lt;&gt;</p>", "tok") is None
