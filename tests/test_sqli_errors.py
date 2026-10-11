import httpx

from conftest import HTML
from owaspscan.checks.base import REGISTRY
from owaspscan.checks.sqli_errors import SqlErrorCheck, db_errors
from owaspscan.cli import build_parser
from owaspscan.config import ScanConfig
from owaspscan.models import Severity

TARGET = "https://example.test/item?id=5"
MYSQL = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"


def app(error_when, status=200, body=MYSQL, content_type=HTML, param="id"):
    """Fake endpoint: responds with `body` when error_when(value) is true, else a normal page."""
    def handler(request):
        value = request.url.params.get(param, "")
        if error_when(value):
            return httpx.Response(status, headers=content_type, text=body)
        return httpx.Response(200, headers=HTML, text="<p>item ok</p>")
    return handler


def odd_quotes(value):
    return value.count("'") % 2 == 1


def run(make_ctx, handler, target=TARGET, max_probes=None):
    ctx = make_ctx(handler, target)
    if max_probes is not None:
        ctx.config.max_probes = max_probes
    return SqlErrorCheck().run(ctx), ctx


def test_is_active_and_defaults():
    assert REGISTRY["sqli-errors"].active is True
    assert ScanConfig(target="https://x.test").max_probes == 150
    assert build_parser().parse_args(["https://x.test"]).max_probes == 150


def test_vulnerable_is_high(make_ctx):
    found, _ = run(make_ctx, app(odd_quotes, status=500))
    assert len(found) == 1 and found[0].severity == Severity.HIGH
    assert "MySQL" in found[0].title and "'id'" in found[0].title


def test_safe_app_is_clean_and_cheap(make_ctx):
    found, ctx = run(make_ctx, app(lambda v: False))
    assert found == [] and ctx.probes_used == 2  # control request not needed


def test_error_text_already_in_baseline_is_ignored(make_ctx):
    found, _ = run(make_ctx, app(lambda v: True))  # every response contains the error text
    assert found == []


def test_any_quote_errors_is_medium(make_ctx):
    found, _ = run(make_ctx, app(lambda v: "'" in v, status=500))
    assert len(found) == 1 and found[0].severity == Severity.MEDIUM


def test_generic_500_without_signature_is_info_only(make_ctx):
    found, _ = run(make_ctx, app(odd_quotes, status=500, body="Internal Server Error"))
    assert len(found) == 1 and found[0].severity == Severity.INFO


def test_waf_block_is_reported_not_flagged(make_ctx):
    found, _ = run(make_ctx, app(odd_quotes, status=403, body="Blocked by firewall"))
    assert [f.severity for f in found] == [Severity.INFO]
    assert "blocked" in found[0].title.lower()


def test_rate_limit_stops_check(make_ctx):
    def handler(request):
        if "'" in request.url.params.get("id", ""):
            return httpx.Response(429, headers=HTML, text="slow down")
        return httpx.Response(200, headers=HTML, text="<p>ok</p>")
    found, ctx = run(make_ctx, handler)
    assert [f.severity for f in found] == [Severity.INFO]
    assert "429" in found[0].evidence and ctx.probes_used == 2


def test_json_error_is_detected(make_ctx):
    handler = app(odd_quotes, status=500, body='{"error": "%s"}' % MYSQL,
                  content_type={"content-type": "application/json"})
    found, _ = run(make_ctx, handler)
    assert found and found[0].severity == Severity.HIGH


def test_binary_content_is_skipped(make_ctx):
    handler = app(odd_quotes, content_type={"content-type": "application/octet-stream"})
    found, _ = run(make_ctx, handler)
    assert found == []


def test_failing_baseline_is_skipped(make_ctx):
    handler = lambda r: httpx.Response(500, headers=HTML, text=MYSQL)
    found, _ = run(make_ctx, handler)
    assert found == []


def test_budget_exhausted_reports_untested(make_ctx):
    page = '<a href="/s?a=1&b=2">x</a>'
    def handler(request):
        return httpx.Response(200, headers=HTML, text=page)
    found, ctx = run(make_ctx, handler, "https://example.test/s?a=1&b=2", max_probes=3)
    assert ctx.probes_used == 2
    assert len(found) == 1 and found[0].severity == Severity.INFO and "1 parameter" in found[0].evidence


def test_get_form_fields_are_tested(make_ctx):
    def handler(request):
        term = request.url.params.get("term", "")
        form = '<form action="/find"><input name="term" value="a"></form>'
        if request.url.path == "/find" and odd_quotes(term):
            return httpx.Response(500, headers=HTML, text=MYSQL)
        return httpx.Response(200, headers=HTML, text=form)
    found, _ = run(make_ctx, handler, "https://example.test/")
    assert any("'term'" in f.title and f.severity == Severity.HIGH for f in found)


def test_signature_unit():
    assert "Oracle" in db_errors("ORA-00933: SQL command not properly ended")
    assert "SQLite" in db_errors('near "x": syntax error')
    assert "PostgreSQL" in db_errors("ERROR: syntax error at or near \"'\"")
    assert db_errors("ORA-123 is a part number, nothing to see") == {}
    assert db_errors("<p>Welcome to our store</p>") == {}
