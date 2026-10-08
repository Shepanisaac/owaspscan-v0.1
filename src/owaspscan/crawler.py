"""Scope-limited crawler: same origin, page cap, polite delay."""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from functools import cached_property
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse, urlunparse

import httpx
from bs4 import BeautifulSoup

from .config import ScanConfig
from .models import Form, InjectionPoint

NON_INPUT_TYPES = {"submit", "button", "image", "reset", "file", "password"}


@dataclass(frozen=True)
class Page:
    url: str
    response: httpx.Response

    @property
    def is_html(self) -> bool:
        return "text/html" in self.response.headers.get("content-type", "")

    @cached_property
    def soup(self) -> BeautifulSoup | None:
        return BeautifulSoup(self.response.text, "html.parser") if self.is_html else None

    @cached_property
    def forms(self) -> tuple[Form, ...]:
        """Forms found on this page, with absolute action URLs."""
        if self.soup is None:
            return ()
        forms = []
        for tag in self.soup.find_all("form"):
            action, _ = urldefrag(urljoin(self.url, tag.get("action") or self.url))
            method = (tag.get("method") or "GET").upper()
            fields = []
            for field in tag.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                if not name or (field.get("type") or "text").lower() in NON_INPUT_TYPES:
                    continue
                fields.append((name, field.get("value") or ""))
            forms.append(Form(action, method, tuple(fields)))
        return tuple(forms)

    @cached_property
    def query_points(self) -> tuple[InjectionPoint, ...]:
        """One injection point per query-string parameter of this page's own URL."""
        parts = urlparse(self.url)
        pairs = tuple(parse_qsl(parts.query, keep_blank_values=True))
        base = urlunparse(parts._replace(query="", fragment=""))
        return tuple(InjectionPoint(base, name, "GET", pairs) for name, _ in pairs)


def extract_links(page: Page) -> list[str]:
    """Return absolute http(s) links found in an HTML page."""
    if page.soup is None:
        return []
    links = []
    for anchor in page.soup.find_all("a", href=True):
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
