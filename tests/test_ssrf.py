import time

import httpx

from conftest import HTML
from owaspscan.checks.base import REGISTRY
from owaspscan.checks.ssrf import SSRFCheck, _looks_fetchable
from owaspscan.models import Severity

TARGET = "https://example.test/preview?url=https://example.com/photo.jpg"


def run(make_ctx, handler, target=TARGET):
    ctx = make_ctx(handler, target)
    return SSRFCheck().run(ctx), ctx


def test_is_active_check():
    assert REGISTRY["ssrf"].active is True


def test_name_matcher():
    for name in ("url", "imageUrl", "webhook", "callback_url", "fetchFrom"):
        assert _looks_fetchable(name)
    for name in ("id", "q", "page", "username"):
        assert not _looks_fetchable(name)


def test_non_fetchable_param_never_probed(make_ctx):
    found, ctx = run(make_ctx, lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"),
                      "https://example.test/item?id=5")
    assert found == [] and ctx.probes_used == 0


def test_clean_app_produces_no_findings(make_ctx):
    found, _ = run(make_ctx, lambda r: httpx.Response(200, headers=HTML, text="<p>ok</p>"))
    assert found == []


def test_redirect_response_is_never_flagged(make_ctx):
    # the app just bounces the browser there (open-redirect's job), not an SSRF signal
    def handler(request):
        value = request.url.params.get("url", "")
        return httpx.Response(302, headers={**HTML, "Location": value})
    found, _ = run(make_ctx, handler)
    assert found == []


def test_metadata_leak_flagged_high(make_ctx):
    def handler(request):
        value = request.url.params.get("url", "")
        if "169.254.169.254" in value:
            return httpx.Response(200, headers=HTML,
                                   text='{"instance-id": "i-0123456789abcdef0"}')
        return httpx.Response(200, headers=HTML, text="<p>preview unavailable</p>")
    found, _ = run(make_ctx, handler)
    assert len(found) == 1
    assert found[0].severity == Severity.HIGH
    assert "cloud metadata" in found[0].title


def test_timing_anomaly_flagged_info(make_ctx, monkeypatch):
    from owaspscan.checks import ssrf as ssrf_module
    monkeypatch.setattr(ssrf_module, "TIMING_ABS_SECONDS", 0.05)
    monkeypatch.setattr(ssrf_module, "TIMING_MULTIPLIER", 1.5)

    def handler(request):
        value = request.url.params.get("url", "")
        if "127.0.0.1:18273" in value:
            time.sleep(0.15)
        return httpx.Response(200, headers=HTML, text="<p>preview unavailable</p>")
    found, _ = run(make_ctx, handler)
    assert len(found) == 1
    assert found[0].severity == Severity.INFO
    assert "unconfirmed" in found[0].title
    assert "No out-of-band canary" in found[0].evidence


def test_fast_consistent_responses_are_clean(make_ctx, monkeypatch):
    from owaspscan.checks import ssrf as ssrf_module
    monkeypatch.setattr(ssrf_module, "TIMING_ABS_SECONDS", 0.05)
    monkeypatch.setattr(ssrf_module, "TIMING_MULTIPLIER", 1.5)
    found, _ = run(make_ctx, lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"))
    assert found == []


def test_probe_cap_respected(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"), TARGET)
    ctx.config.max_probes = 0
    SSRFCheck().run(ctx)
    assert ctx.probes_used == 0
