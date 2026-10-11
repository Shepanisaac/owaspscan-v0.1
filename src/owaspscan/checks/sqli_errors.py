"""A03: error-based SQL injection hints (active, GET only, detection only).

For each GET parameter we compare three responses: the normal value, the value plus a
single quote, and (only if the quote looks suspicious) the value plus a balanced pair ''.
A database error that appears for ' but not for the baseline or for '' is strong evidence
that the input reaches a query unsafely. Nothing is read or modified.
"""
from __future__ import annotations

import re

from ..models import Finding, InjectionPoint, Severity
from .base import Check, ScanContext, register

MAX_SCAN_CHARS = 200_000
SCANNABLE_TYPES = ("text/", "json", "xml")
BLOCK_STATUSES = (403, 406)
PROBES_PER_POINT = 2  # baseline + quote; the control request is only sent when needed

SIGNATURES: dict[str, tuple[str, ...]] = {
    "MySQL/MariaDB": (
        r"You have an error in your SQL syntax",
        r"check the manual that (?:corresponds to|fits) your (?:MySQL|MariaDB) server version",
        r"Warning.{0,40}\bmysqli?_",
        r"com\.mysql\.jdbc",
        r"MySqlException",
    ),
    "PostgreSQL": (
        r"PostgreSQL.{0,40}ERROR",
        r"unterminated quoted string at or near",
        r"org\.postgresql\.util\.PSQLException",
        r"Warning.{0,40}\bpg_",
        r"syntax error at or near",
    ),
    "SQL Server": (
        r"Unclosed quotation mark after the character string",
        r"Microsoft OLE DB Provider for SQL Server",
        r"\[Microsoft\]\[ODBC SQL Server Driver\]",
        r"System\.Data\.SqlClient\.SqlException",
        r"Incorrect syntax near",
    ),
    "Oracle": (
        r"\bORA-\d{5}\b",
        r"quoted string not properly terminated",
    ),
    "SQLite": (
        r"SQLITE_ERROR",
        r"sqlite3\.OperationalError",
        r"SQLite3::SQLException",
        r"unrecognized token:",
        r"near \".{0,40}\": syntax error",
    ),
    "Generic": (
        r"SQLSTATE\[\w+\]",
        r"PDOException",
        r"java\.sql\.SQL\w*Exception",
    ),
}
COMPILED = {db: [re.compile(p, re.IGNORECASE) for p in patterns] for db, patterns in SIGNATURES.items()}


def db_errors(text: str) -> dict[str, str]:
    """Map database name -> short matched snippet, for every signature found in text."""
    found: dict[str, str] = {}
    for db, patterns in COMPILED.items():
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                found[db] = " ".join(match.group(0).split())[:100]
                break
    return found


def _errors_in(response) -> dict[str, str]:
    """Signatures in a response, ignoring binary content and capping the text scanned."""
    kind = response.headers.get("content-type", "").lower()
    if not any(token in kind for token in SCANNABLE_TYPES):
        return {}
    return db_errors(response.text[:MAX_SCAN_CHARS])


@register
class SqlErrorCheck(Check):
    id = "sqli-errors"
    category = "A03"
    description = "Database error messages triggered by a quote (error-based SQLi hint)"
    active = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        blocked: list[str] = []
        untested = 0
        stopped_by: str | None = None
        points = ctx.injection_points

        for position, point in enumerate(points):
            if ctx.config.max_probes - ctx.probes_used < PROBES_PER_POINT:
                untested = len(points) - position
                stopped_by = "probe budget"
                break
            outcome = self._test_point(ctx, point, findings, blocked)
            if outcome == "rate-limited":
                untested = len(points) - position - 1
                stopped_by = "HTTP 429 (rate limited)"
                break

        if blocked:
            findings.append(self.finding(
                "Probes were blocked by a firewall or filter", Severity.INFO, ctx.landing.url,
                f"Parameters answered 403/406 to a quote: {', '.join(blocked[:5])}. "
                "These could not be tested.", "Test from an allow-listed address if appropriate."))
        if stopped_by:
            findings.append(self.finding(
                "SQL error check did not cover every parameter", Severity.INFO, ctx.landing.url,
                f"Stopped early ({stopped_by}); {untested} parameter(s) were not tested.",
                "Raise --max-probes, scan fewer pages, or rerun later."))
        return findings

    def _test_point(self, ctx, point: InjectionPoint, findings, blocked) -> str:
        base = dict(point.params).get(point.param, "") or "1"

        def send(value):
            return ctx.probe(point.url, params=point.request_params(value))

        baseline = send(base)
        if baseline is None:
            return "skipped"
        if baseline.status_code == 429:
            return "rate-limited"
        if baseline.status_code >= 400:
            return "skipped"  # endpoint already failing or blocked: nothing to compare against

        probe = send(base + "'")
        if probe is None:
            return "skipped"
        if probe.status_code == 429:
            return "rate-limited"
        if probe.status_code in BLOCK_STATUSES:
            blocked.append(point.param)
            return "blocked"

        baseline_dbs = _errors_in(baseline)
        new = {db: s for db, s in _errors_in(probe).items() if db not in baseline_dbs}

        if new:
            db, snippet = next(iter(new.items()))
            control = send(base + "''")
            control_new = {} if control is None else {
                d for d in _errors_in(control) if d not in baseline_dbs}
            clean_control = control is not None and db not in control_new
            severity = Severity.HIGH if clean_control else Severity.MEDIUM
            detail = ("the baseline and the balanced '' request did not" if clean_control
                      else "the balanced '' request also errored, or could not be sent, "
                           "so manual review is needed")
            findings.append(self.finding(
                f"Possible SQL injection (error-based, {db}) in parameter '{point.param}'",
                severity, point.url,
                f"Adding ' produced a {db} error ({snippet}); {detail}.",
                "Use parameterized queries / prepared statements, never build SQL from input, "
                "and hide database errors from users."))
        elif probe.status_code >= 500:
            findings.append(self.finding(
                f"Unhandled server error on a quote in parameter '{point.param}'",
                Severity.INFO, point.url,
                f"Adding ' returned HTTP {probe.status_code} with no known database error text; "
                "the baseline succeeded.", "Review manually; handle bad input without a 500."))
        return "done"
