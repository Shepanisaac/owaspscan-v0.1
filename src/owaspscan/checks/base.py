"""Check base class, scan context, and the registry."""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from ..config import ScanConfig
from ..crawler import Page
from ..models import Finding, InjectionPoint, Severity


@dataclass
class ScanContext:
    config: ScanConfig
    client: httpx.Client
    pages: list[Page]
    probes_used: int = 0

    @property
    def landing(self) -> Page:
        return self.pages[0]

    @property
    def origin(self) -> str:
        parts = urlparse(self.landing.url)
        return f"{parts.scheme}://{parts.netloc}"

    @property
    def injection_points(self) -> list[InjectionPoint]:
        """Unique GET injection points from page URLs and GET forms (POST is never included)."""
        seen: set[tuple[str, str, str]] = set()
        points: list[InjectionPoint] = []
        for page in self.pages:
            candidates = list(page.query_points)
            for form in page.forms:
                candidates += form.injection_points()
            for point in candidates:
                key = (point.url, point.param, point.method)
                if key not in seen:
                    seen.add(key)
                    points.append(point)
        return points

    def probe(self, url: str, params: dict[str, str] | None = None,
              headers: dict[str, str] | None = None) -> httpx.Response | None:
        """Send one GET probe. Enforces the probe cap and delay; returns None on cap or error.

        All active checks must send their requests through here.
        """
        if self.probes_used >= self.config.max_probes:
            return None
        self.probes_used += 1
        time.sleep(self.config.delay)
        try:
            return self.client.get(url, params=params, headers=headers)
        except httpx.HTTPError:
            return None


class Check(ABC):
    id: str
    category: str
    description: str = ""
    active: bool = False  # True = sends probe requests; only runs with --active

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]:
        """Inspect the context and return findings. Must not raise on normal input."""

    def finding(self, title: str, severity: Severity, url: str,
                evidence: str, remediation: str) -> Finding:
        return Finding(self.category, self.id, title, severity, url, evidence, remediation)


REGISTRY: dict[str, type[Check]] = {}


def register(cls: type[Check]) -> type[Check]:
    REGISTRY[cls.id] = cls
    return cls
