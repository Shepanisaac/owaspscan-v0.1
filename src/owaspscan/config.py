"""Scan configuration."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    target: str
    max_pages: int = 25
    delay: float = 0.2
    timeout: float = 10.0
    cookies: dict[str, str] = field(default_factory=dict)
    enabled_checks: list[str] | None = None  # None = all registered checks
    active: bool = False  # allow checks that send modified (probe) requests
    max_probes: int = 150  # hard cap on probe requests per scan
    # URLs containing these fragments are never requested (GET can have side effects).
    exclude: tuple[str, ...] = ("logout", "signout", "delete", "remove")
    user_agent: str = "owaspscan/0.1 (authorized security testing)"
