"""A02: legacy TLS versions and certificate problems (passive: opens plain TLS connections only)."""
from __future__ import annotations

import socket
import ssl
import time
import warnings
from urllib.parse import urlparse

from ..models import Finding, Severity
from .base import Check, ScanContext, register

ACCEPTED, REJECTED, UNTESTABLE = "accepted", "rejected", "untestable"

LEGACY = (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1))
EXPIRY_WARNING_DAYS = 30
TIMEOUT = 5.0

# Errors that mean *our* client could not even try the protocol (never treated as "safe").
_CLIENT_LIMIT = ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE")
# Errors that mean the *server* refused the protocol version.
_SERVER_REFUSED = ("PROTOCOL_VERSION", "WRONG_VERSION_NUMBER", "UNSUPPORTED_PROTOCOL",
                   "HANDSHAKE_FAILURE", "ALERT")


def _classify_handshake_error(exc: ssl.SSLError) -> str:
    text = str(exc).upper()
    if any(marker in text for marker in _CLIENT_LIMIT):
        return UNTESTABLE
    if any(marker in text for marker in _SERVER_REFUSED):
        return REJECTED
    return UNTESTABLE  # unknown error: never claim the server is safe


def _handshake_result(host: str, port: int, version: ssl.TLSVersion) -> str:
    """Try to complete a handshake restricted to exactly one protocol version."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")  # allow offering legacy protocols
    except ssl.SSLError:
        pass
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)  # legacy versions are the point
            context.minimum_version = version
            context.maximum_version = version
    except (ValueError, ssl.SSLError):
        return UNTESTABLE
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return ACCEPTED
    except ssl.SSLError as exc:
        return _classify_handshake_error(exc)
    except OSError:
        return UNTESTABLE


def _cert_status(host: str, port: int) -> tuple[str, int | str | None]:
    """Return ("ok", days_left), ("invalid", reason) or ("error", None)."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        expires = ssl.cert_time_to_seconds(cert["notAfter"])
        return "ok", int((expires - time.time()) // 86400)
    except ssl.SSLCertVerificationError as exc:  # must come before SSLError/OSError
        return "invalid", exc.verify_message or str(exc)
    except (OSError, KeyError, ValueError):
        return "error", None


@register
class TlsCheck(Check):
    id = "tls"
    category = "A02"
    description = "Legacy TLS 1.0/1.1 support and certificate problems"

    def run(self, ctx: ScanContext) -> list[Finding]:
        page = ctx.landing
        parts = urlparse(page.url)
        if parts.scheme != "https" or not parts.hostname:
            return []
        host, port = parts.hostname, parts.port or 443
        findings: list[Finding] = []

        status, detail = _cert_status(host, port)
        if status == "invalid":
            findings.append(self.finding(
                "TLS certificate failed validation", Severity.HIGH, page.url,
                f"Certificate verification error: {detail}",
                "Install a valid certificate from a trusted CA that matches the hostname."))
        elif status == "ok" and detail <= EXPIRY_WARNING_DAYS:
            severity = Severity.MEDIUM if detail <= 7 else Severity.LOW
            findings.append(self.finding(
                "TLS certificate expires soon", severity, page.url,
                f"Certificate expires in {detail} day(s).",
                "Renew the certificate and consider automated renewal (e.g. Let's Encrypt)."))

        untestable: list[str] = []
        for name, version in LEGACY:
            result = _handshake_result(host, port, version)
            if result == ACCEPTED:
                findings.append(self.finding(
                    f"Server accepts {name}", Severity.MEDIUM, page.url,
                    f"A handshake restricted to {name} succeeded.",
                    "Disable TLS 1.0 and 1.1; allow only TLS 1.2 and 1.3."))
            elif result == UNTESTABLE:
                untestable.append(name)
        if untestable:
            findings.append(self.finding(
                "Legacy TLS versions could not be tested", Severity.INFO, page.url,
                f"This machine's TLS library could not offer: {', '.join(untestable)}. "
                "This is not evidence that the server is safe.",
                "Verify with an external tool such as SSL Labs or testssl.sh."))
        return findings
