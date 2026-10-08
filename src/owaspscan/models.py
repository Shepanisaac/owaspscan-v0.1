"""Core data models shared across the scanner."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3


# Single place to edit when moving to a newer OWASP Top 10 edition.
CATEGORIES: dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}


@dataclass(frozen=True)
class Finding:
    category: str
    check_id: str
    title: str
    severity: Severity
    url: str
    evidence: str
    remediation: str

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.name
        data["category_name"] = CATEGORIES.get(self.category, "Unknown")
        return data


@dataclass(frozen=True)
class InjectionPoint:
    """One place where input can be sent: a single parameter of a GET endpoint."""

    url: str  # endpoint without a query string
    param: str
    method: str = "GET"
    params: tuple[tuple[str, str], ...] = ()  # every parameter with its default value

    def request_params(self, value: str) -> dict[str, str]:
        """All parameters with this point's parameter set to `value`."""
        return {k: (value if k == self.param else v) for k, v in self.params}


@dataclass(frozen=True)
class Form:
    action: str  # absolute URL
    method: str  # "GET" or "POST"
    fields: tuple[tuple[str, str], ...] = ()  # (name, default value)

    def injection_points(self) -> list[InjectionPoint]:
        """GET forms only. POST forms are listed but never submitted."""
        if self.method != "GET":
            return []
        return [InjectionPoint(self.action, name, "GET", self.fields) for name, _ in self.fields]
