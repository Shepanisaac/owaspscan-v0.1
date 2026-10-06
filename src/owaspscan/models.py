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
