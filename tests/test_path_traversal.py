import httpx

from conftest import HTML
from owaspscan.checks.base import REGISTRY
from owaspscan.checks.path_traversal import PathTraversalCheck, _looks_file_like
from owaspscan.models import Severity

TARGET = "https://example.test/download?file=report.pdf"


def run(make_ctx, handler, target=TARGET):
    ctx = make_ctx(handler, target)
    return PathTraversalCheck().run(ctx), ctx


def test_is_active_check():
    assert REGISTRY["path-traversal"].active is True


def test_name_matcher():
    for name in ("file", "filename", "path", "template", "includePage", "download"):
        assert _looks_file_like(name)
    for name in ("id", "q", "username", "color"):
        assert not _looks_file_like(name)


def test_non_file_param_never_probed(make_ctx):
    found, ctx = run(make_ctx, lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"),
                      "https://example.test/item?id=5")
    assert found == [] and ctx.probes_used == 0


def test_clean_app_produces_no_findings(make_ctx):
    found, _ = run(make_ctx, lambda r: httpx.Response(200, headers=HTML, text="<p>report</p>"))
    assert found == []


def test_unix_traversal_confirmed_flagged_high(make_ctx):
    def handler(request):
        value = request.url.params.get("file", "")
        if "etc/passwd" in value:
            return httpx.Response(200, headers=HTML, text="root:x:0:0:root:/root:/bin/bash\n")
        return httpx.Response(200, headers=HTML, text="<p>report</p>")
    found, _ = run(make_ctx, handler)
    assert len(found) == 1
    assert found[0].severity == Severity.HIGH
    assert "Unix" in found[0].title


def test_windows_traversal_confirmed_flagged_high(make_ctx):
    def handler(request):
        value = request.url.params.get("file", "")
        if "win.ini" in value:
            return httpx.Response(200, headers=HTML, text="[fonts]\n[extensions]\n")
        return httpx.Response(200, headers=HTML, text="<p>report</p>")
    found, _ = run(make_ctx, handler)
    assert len(found) == 1 and "Windows" in found[0].title


def test_stops_after_first_confirmed_payload(make_ctx):
    calls = []
    def handler(request):
        value = request.url.params.get("file", "")
        calls.append(value)
        if "etc/passwd" in value:
            return httpx.Response(200, headers=HTML, text="root:x:0:0:root:/root:/bin/bash\n")
        return httpx.Response(200, headers=HTML, text="<p>report</p>")
    found, ctx = run(make_ctx, handler)
    assert len(found) == 1 and ctx.probes_used == 1  # second payload never sent


def test_reflected_payload_without_marker_content_is_clean(make_ctx):
    # app reflects the raw parameter value back (e.g. in an error message) but never
    # actually read the file — no marker content, so this must not be flagged
    def handler(request):
        value = request.url.params.get("file", "")
        return httpx.Response(404, headers=HTML, text=f"File not found: {value}")
    found, _ = run(make_ctx, handler)
    assert found == []


def test_binary_content_type_not_scanned(make_ctx):
    def handler(request):
        return httpx.Response(200, headers={"content-type": "application/pdf"},
                               text="root:x:0:0:root:/root:/bin/bash\n")
    found, _ = run(make_ctx, handler)
    assert found == []


def test_probe_cap_respected(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(200, headers=HTML, text="<p>x</p>"), TARGET)
    ctx.config.max_probes = 0
    PathTraversalCheck().run(ctx)
    assert ctx.probes_used == 0
