"""Scope-limited crawler: same origin, page cap, polite delay."""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from urllib.parse import urldefrag, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .config import ScanConfig


@dataclass(frozen=True)
class Page:
    url: str
    response: httpx.Response

    @property
    def is_html(self) -> bool:
        return "text/html" in self.response.headers.get("content-type", "")


def extract_links(page: Page) -> list[str]:
    """Return absolute http(s) links found in an HTML page."""
    if not page.is_html:
        return []
    soup = BeautifulSoup(page.response.text, "html.parser")
    links = []
    for anchor in soup.find_all("a", href=True):
        url, _ = urldefrag(urljoin(page.url, anchor["href"]))
        if urlparse(url).scheme in ("http", "https"):
            links.append(url)
    return links


def crawl(client: httpx.Client, config: ScanConfig) -> list[Page]:
    """Breadth-first crawl starting at config.target, never leaving its host."""
    queue = deque([config.target])
    seen = {config.target}
    pages: list[Page] = []
    host: str | None = None

    while queue and len(pages) < config.max_pages:
        url = queue.popleft()
        try:
            response = client.get(url)
        except httpx.HTTPError:
            continue
        page = Page(str(response.url), response)
        pages.append(page)
        host = host or urlparse(page.url).netloc  # host after any initial redirect

        for link in extract_links(page):
            skip = any(word in link.lower() for word in config.exclude)
            if link not in seen and urlparse(link).netloc == host and not skip:
                seen.add(link)
                queue.append(link)
        time.sleep(config.delay)
    return pages
