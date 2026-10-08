import ssl

import httpx

from conftest import HTML
from owaspscan.checks import tls
from owaspscan.checks.base import REGISTRY
from owaspscan.checks.cors import CorsCheck
from owaspscan.checks.tls import ACCEPTED, REJECTED, UNTESTABLE, TlsCheck
from owaspscan.models import Severity

PAGE = httpx.Response(200, headers=HTML, text="<html></html>")


def page_handler(request):
    return httpx.Response(200, headers=HTML, text="<html></html>")


def titles(findings):
    return {f.title for f in findings}


# ---------- tls ----------

def patch_tls(monkeypatch, cert=("ok", 200), handshake=REJECTED):
    monkeypatch.setattr(tls, "_cert_status", lambda host, port: cert)
    monkeypatch.setattr(tls, "_handshake_result", lambda host, port, version: handshake)


def test_tls_skips_plain_http(make_ctx, monkeypatch):
    monkeypatch.setattr(tls, "_cert_status", lambda *a: (_ for _ in ()).throw(AssertionError))
    ctx = make_ctx(page_handler, "http://example.test/")
    assert TlsCheck().run(ctx) == []


def test_tls_clean_server(make_ctx, monkeypatch):
    patch_tls(monkeypatch)
    assert TlsCheck().run(make_ctx(page_handler)) == []


def test_tls_legacy_accepted(make_ctx, monkeypatch):
    patch_tls(monkeypatch, handshake=ACCEPTED)
    found = TlsCheck().run(make_ctx(page_handler))
    assert titles(found) == {"Server accepts TLS 1.0", "Server accepts TLS 1.1"}
    assert all(f.severity == Severity.MEDIUM for f in found)


def test_tls_untestable_is_info_not_safe(make_ctx, monkeypatch):
    patch_tls(monkeypatch, handshake=UNTESTABLE)
    found = TlsCheck().run(make_ctx(page_handler))
    assert len(found) == 1 and found[0].severity == Severity.INFO
    assert "not evidence" in found[0].evidence


def test_tls_certificate_expiry(make_ctx, monkeypatch):
    patch_tls(monkeypatch, cert=("ok", 20))
    assert TlsCheck().run(make_ctx(page_handler))[0].severity == Severity.LOW
    patch_tls(monkeypatch, cert=("ok", 3))
    assert TlsCheck().run(make_ctx(page_handler))[0].severity == Severity.MEDIUM


def test_tls_invalid_certificate(make_ctx, monkeypatch):
    patch_tls(monkeypatch, cert=("invalid", "certificate has expired"))
    found = TlsCheck().run(make_ctx(page_handler))
    assert found[0].severity == Severity.HIGH and "expired" in found[0].evidence


def test_tls_cert_lookup_error_is_silent(make_ctx, monkeypatch):
    patch_tls(monkeypatch, cert=("error", None))
    assert TlsCheck().run(make_ctx(page_handler)) == []


def test_classify_handshake_errors():
    assert tls._classify_handshake_error(ssl.SSLError("[SSL: TLSV1_ALERT_PROTOCOL_VERSION]")) == REJECTED
    assert tls._classify_handshake_error(ssl.SSLError("[SSL: NO_PROTOCOLS_AVAILABLE]")) == UNTESTABLE
    assert tls._classify_handshake_error(ssl.SSLError("something odd")) == UNTESTABLE


# ---------- cors ----------

def cors_handler(rule, credentials=True):
    """rule(origin) -> Access-Control-Allow-Origin value or None."""
    def handler(request):
        headers = dict(HTML)
        origin = request.headers.get("origin")
        if origin and (allowed := rule(origin)):
            headers["access-control-allow-origin"] = allowed
            if credentials:
                headers["access-control-allow-credentials"] = "true"
        return httpx.Response(200, headers=headers, text="<html></html>")
    return handler


def test_cors_is_active_check():
    assert REGISTRY["cors"].active is True and REGISTRY["tls"].active is False


def test_cors_reflected_with_credentials_is_high(make_ctx):
    found = CorsCheck().run(make_ctx(cors_handler(lambda o: o)))
    top = max(found, key=lambda f: f.severity)
    assert top.severity == Severity.HIGH and "any origin" in top.title
    assert not any("look-alike" in f.title for f in found)  # covered by 'arbitrary'


def test_cors_reflected_without_credentials_is_low(make_ctx):
    found = CorsCheck().run(make_ctx(cors_handler(lambda o: o, credentials=False)))
    assert found and max(f.severity for f in found) == Severity.LOW


def test_cors_fixed_trusted_origin_is_clean(make_ctx):
    assert CorsCheck().run(make_ctx(cors_handler(lambda o: "https://example.test"))) == []


def test_cors_no_cors_headers_is_clean(make_ctx):
    assert CorsCheck().run(make_ctx(page_handler)) == []


def test_cors_null_origin(make_ctx):
    found = CorsCheck().run(make_ctx(cors_handler(lambda o: o if o == "null" else None)))
    assert titles(found) == {"CORS trusts the 'null' origin with credentials"}
    assert found[0].severity == Severity.HIGH


def test_cors_lookalike_origin(make_ctx):
    rule = lambda o: o if o.startswith("https://example.test") else None  # buggy prefix match
    found = CorsCheck().run(make_ctx(cors_handler(rule)))
    assert titles(found) == {"CORS trusts look-alike origins (weak origin matching) with credentials"}


def test_cors_wildcard_is_info(make_ctx):
    found = CorsCheck().run(make_ctx(cors_handler(lambda o: "*", credentials=False)))
    assert len(found) == 1 and found[0].severity == Severity.INFO


def test_cors_respects_probe_cap(make_ctx):
    ctx = make_ctx(cors_handler(lambda o: o))
    ctx.config.max_probes = 1
    CorsCheck().run(ctx)
    assert ctx.probes_used == 1
