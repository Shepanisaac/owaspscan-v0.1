"""Check base class, scan context, and the registry."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from ..config import ScanConfig
from ..crawler import Page
from ..models import Finding, Severity


@dataclass
class ScanContext:
    config: ScanConfig
    client: httpx.Client
    pages: list[Page]

    @property
    def landing(self) -> Page:
        return self.pages[0]

    @property
    def origin(self) -> str:
        parts = urlparse(self.landing.url)
        return f"{parts.scheme}://{parts.netloc}"


class Check(ABC):
    id: str
    category: str
    description: str = ""

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
