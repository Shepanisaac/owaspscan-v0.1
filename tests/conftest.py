import httpx
import pytest

from owaspscan.checks.base import ScanContext
from owaspscan.config import ScanConfig
from owaspscan.crawler import crawl

HTML = {"content-type": "text/html"}


@pytest.fixture(autouse=True)
def no_real_tls(monkeypatch):
    """Tests must never open real network connections; TLS tests patch these themselves."""
    from owaspscan.checks import tls
    monkeypatch.setattr(tls, "_cert_status", lambda host, port: ("ok", 365))
    monkeypatch.setattr(tls, "_handshake_result", lambda host, port, version: tls.REJECTED)


@pytest.fixture
def make_ctx():
    def _make(handler, target="https://example.test/", cookies=None):
        transport = httpx.MockTransport(handler)
        config = ScanConfig(target=target, delay=0, cookies=cookies or {})
        client = httpx.Client(transport=transport, follow_redirects=True, cookies=config.cookies)
        return ScanContext(config, client, crawl(client, config), transport=transport)
    return _make
