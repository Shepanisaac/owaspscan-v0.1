import httpx
import pytest

from owaspscan.checks.base import ScanContext
from owaspscan.config import ScanConfig
from owaspscan.crawler import crawl

HTML = {"content-type": "text/html"}


@pytest.fixture
def make_ctx():
    def _make(handler, target="https://example.test/"):
        client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
        config = ScanConfig(target=target, delay=0)
        return ScanContext(config, client, crawl(client, config))
    return _make
