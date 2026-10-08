import httpx
import pytest

from conftest import HTML
from owaspscan.checks.base import REGISTRY, Check
from owaspscan.cli import main
from owaspscan.config import ScanConfig
from owaspscan.engine import run_scan
from owaspscan.models import Severity

PAGE = """
<a href="/search?q=test&page=2">s</a>
<form action="/find" method="get"><input name="term" value="x"><input type="submit" name="go">
  <input type="password" name="pw"></form>
<form action="/login" method="post"><input name="user"><input name="pass"></form>
"""


def handler(request):
    return httpx.Response(200, headers=HTML, text=PAGE)


def test_forms_extracted(make_ctx):
    forms = make_ctx(handler).landing.forms
    assert [(f.action, f.method) for f in forms] == [
        ("https://example.test/find", "GET"), ("https://example.test/login", "POST")]
    assert forms[0].fields == (("term", "x"),)  # submit and password inputs skipped


def test_query_points_keep_other_params(make_ctx):
    ctx = make_ctx(handler, "https://example.test/search?q=test&page=2")
    point = next(p for p in ctx.landing.query_points if p.param == "q")
    assert point.url == "https://example.test/search"
    assert point.request_params("MARK") == {"q": "MARK", "page": "2"}


def test_injection_points_are_get_only_and_unique(make_ctx):
    ctx = make_ctx(handler)
    keys = {(p.url, p.param) for p in ctx.injection_points}
    assert ("https://example.test/find", "term") in keys
    assert ("https://example.test/search", "q") in keys
    assert not any(url.endswith("/login") for url, _ in keys)  # POST form excluded
    assert len(ctx.injection_points) == len(keys)


def test_probe_respects_cap_and_handles_errors(make_ctx):
    ctx = make_ctx(handler)
    ctx.config.max_probes = 2
    assert ctx.probe("https://example.test/a") is not None
    assert ctx.probe("https://example.test/b") is not None
    assert ctx.probe("https://example.test/c") is None
    assert ctx.probes_used == 2


@pytest.fixture
def fake_active():
    class FakeActive(Check):
        id = "fake-active"
        category = "A03"
        active = True
        description = "test only"

        def run(self, ctx):
            ctx.probe(ctx.origin + "/probe")
            return [self.finding("probe ran", Severity.INFO, ctx.landing.url, "e", "r")]

    REGISTRY["fake-active"] = FakeActive
    yield FakeActive
    REGISTRY.pop("fake-active", None)


def scan(**kwargs):
    config = ScanConfig(target="https://example.test/", delay=0, **kwargs)
    return run_scan(config, transport=httpx.MockTransport(handler))


def test_active_check_skipped_by_default(fake_active):
    result = scan()
    assert not result.active
    assert all(f.check_id != "fake-active" for f in result.findings)


def test_active_check_runs_with_flag(fake_active):
    result = scan(active=True)
    assert any(f.check_id == "fake-active" for f in result.findings)
    assert result.active and result.probes_sent == 1


def test_explicit_active_check_without_flag_is_rejected(fake_active):
    with pytest.raises(ValueError, match="--active"):
        scan(enabled_checks=["fake-active"])


def test_list_checks_shows_mode(capsys):
    assert main(["--list-checks"]) == 0
    assert "passive" in capsys.readouterr().out
