import re
import time

import httpx
import pytest

from conftest import HTML
from owaspscan.checks.base import REGISTRY
from owaspscan.checks.sqli_blind import BlindSqliCheck
from owaspscan.models import Severity

SLEEP_PATTERN = re.compile(r"SLEEP\((\d+(?:\.\d+)?)\)|pg_sleep\((\d+(?:\.\d+)?)\)|"
                            r"WAITFOR DELAY '0:0:(\d+(?:\.\d+)?)'", re.IGNORECASE)


@pytest.fixture(autouse=True)
def fast_constants(monkeypatch):
    from owaspscan.checks import sqli_blind as mod
    monkeypatch.setattr(mod, "STAGE1_SLEEP", 0.05)
    monkeypatch.setattr(mod, "STAGE2_SLEEP", 0.15)
    monkeypatch.setattr(mod, "MIN_SIGNAL_SECONDS", 0.03)
    monkeypatch.setattr(mod, "EXTRA_GAP_SECONDS", 0)


def _requested_sleep(value: str) -> float | None:
    match = SLEEP_PATTERN.search(value)
    if not match:
        return None
    return float(next(g for g in match.groups() if g is not None))


def vulnerable_handler(request):
    value = request.url.params.get("id", "")
    seconds = _requested_sleep(value)
    if seconds:
        time.sleep(seconds)
    return httpx.Response(200, headers=HTML, text="<p>ok</p>")


def clean_handler(request):
    return httpx.Response(200, headers=HTML, text="<p>ok</p>")


def run(make_ctx, handler, target="https://example.test/item?id=1"):
    ctx = make_ctx(handler, target)
    return BlindSqliCheck().run(ctx), ctx


def test_is_active_check():
    assert REGISTRY["sqli-blind"].active is True


def test_clean_app_produces_no_findings(make_ctx):
    found, _ = run(make_ctx, clean_handler)
    assert found == []


def test_vulnerable_app_flagged_high(make_ctx):
    found, _ = run(make_ctx, vulnerable_handler)
    assert len(found) == 1
    assert found[0].severity == Severity.HIGH
    assert "id" in found[0].title


def test_one_off_slow_response_not_confirmed(make_ctx):
    # stage 1 looks slow, but the server doesn't actually scale with the sleep amount
    # requested (a flat, fixed delay unrelated to the payload) -> must not confirm
    def handler(request):
        value = request.url.params.get("id", "")
        if _requested_sleep(value) is not None:
            time.sleep(0.05)  # same delay regardless of stage1 vs stage2 sleep amount
        return httpx.Response(200, headers=HTML, text="<p>ok</p>")
    found, _ = run(make_ctx, handler)
    assert found == []


def test_max_targets_respected(make_ctx):
    from owaspscan.checks import sqli_blind as mod
    target = "https://example.test/item?a=1&b=2&c=3&d=4&e=5&f=6"
    ctx = make_ctx(clean_handler, target)
    found = BlindSqliCheck().run(ctx)
    assert any("did not cover every parameter" in f.title for f in found)


def test_probe_budget_stops_the_check(make_ctx):
    ctx = make_ctx(clean_handler, "https://example.test/item?id=1")
    ctx.config.max_probes = 0
    found = BlindSqliCheck().run(ctx)
    assert ctx.probes_used == 0
    assert found == []


def test_non_fetchable_point_with_no_params_is_clean(make_ctx):
    found, ctx = run(make_ctx, clean_handler, "https://example.test/")
    assert found == [] and ctx.probes_used == 0
