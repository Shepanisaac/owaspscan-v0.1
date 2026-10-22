"""A03: time-based blind SQL injection (active, GET only). Complements `sqli-errors`:
that check needs a visible database error; this one looks for a parameter that can make
the database itself pause, which also catches injection points where errors are
suppressed.

A sleep payload makes the TARGET DATABASE actually sleep for that long, so this is more
invasive than every other active check in this tool and gets its own, smaller safety
budget on top of the normal --max-probes cap:
  - only the first MAX_TARGETS parameters are tested at all, however many the crawl found;
  - each candidate gets a short (STAGE1_SLEEP) probe, and only if that alone shows a timing
    gap does a second, longer (STAGE2_SLEEP) probe run to confirm the delay actually scales
    with the requested sleep duration — ruling out one-off network/server jitter rather
    than reporting on a single slow response;
  - an extra pause (EXTRA_GAP_SECONDS) runs before every sleep-payload probe, on top of the
    normal --delay, specifically to avoid stacking load on a database that just paused.
Only one engine's payload per parameter is confirmed; the rest are skipped once one hits.
"""
from __future__ import annotations

import time

from ..models import Finding, Severity
from .base import Check, ScanContext, register

MAX_TARGETS = 5          # hard cap on parameters tested with sleep payloads, independent
                          # of --max-probes — this check is more invasive than the others
STAGE1_SLEEP = 1          # seconds requested by the first, exploratory payload
STAGE2_SLEEP = 3          # seconds requested by the confirmation payload, if stage 1 hints
MIN_SIGNAL_SECONDS = 0.6  # stage 1's (elapsed - control) must clear this to even consider it
EXTRA_GAP_SECONDS = 1.0   # extra pause before each sleep-payload probe, beyond --delay

ENGINES = (
    ("MySQL/MariaDB", "' AND SLEEP({n})-- -"),
    ("PostgreSQL", "'; SELECT pg_sleep({n})-- -"),
    ("SQL Server", "'; WAITFOR DELAY '0:0:{n}'--"),
)


def _timed_probe(ctx: ScanContext, url: str, params: dict[str, str]):
    start = time.perf_counter()
    response = ctx.probe(url, params=params)
    return response, time.perf_counter() - start


@register
class BlindSqliCheck(Check):
    id = "sqli-blind"
    category = "A03"
    description = "Time-based blind SQL injection via sleep payloads (two-stage confirmed)"
    active = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        points = ctx.injection_points
        targets = points[:MAX_TARGETS]
        findings: list[Finding] = []

        for point in targets:
            result = self._test_point(ctx, point)
            if result == "budget":
                break
            if isinstance(result, Finding):
                findings.append(result)

        skipped = len(points) - len(targets)
        if skipped > 0:
            findings.append(self.finding(
                "Blind SQLi check did not cover every parameter", Severity.INFO, ctx.landing.url,
                f"Only the first {MAX_TARGETS} parameter(s) are tested with sleep payloads, "
                f"to limit load placed on the target database; {skipped} parameter(s) were "
                "not tested.",
                "Rerun with --checks sqli-blind against a narrower set of pages if you need "
                "to cover the rest."))
        return findings

    def _test_point(self, ctx: ScanContext, point) -> Finding | str | None:
        base = dict(point.params).get(point.param, "") or "1"
        control, control_time = _timed_probe(ctx, point.url, point.request_params(base))
        if control is None:
            return "budget" if ctx.probes_used >= ctx.config.max_probes else None

        for engine_name, template in ENGINES:
            time.sleep(EXTRA_GAP_SECONDS)
            payload1 = template.format(n=STAGE1_SLEEP)
            resp1, t1 = _timed_probe(ctx, point.url, point.request_params(payload1))
            if resp1 is None:
                if ctx.probes_used >= ctx.config.max_probes:
                    return "budget"
                continue
            if t1 - control_time < MIN_SIGNAL_SECONDS:
                continue  # no candidate signal for this engine

            time.sleep(EXTRA_GAP_SECONDS)
            payload2 = template.format(n=STAGE2_SLEEP)
            resp2, t2 = _timed_probe(ctx, point.url, point.request_params(payload2))
            if resp2 is None:
                if ctx.probes_used >= ctx.config.max_probes:
                    return "budget"
                continue

            expected_extra = (STAGE2_SLEEP - STAGE1_SLEEP) * 0.5  # slack, but must scale
            if (t2 - t1) >= expected_extra:
                return self.finding(
                    f"Possible time-based blind SQL injection via parameter "
                    f"'{point.param}' ({engine_name})", Severity.HIGH, point.url,
                    f"A {STAGE1_SLEEP}s sleep payload added {t1 - control_time:.1f}s versus "
                    f"the baseline, and a {STAGE2_SLEEP}s payload added a further "
                    f"{t2 - t1:.1f}s on top of that — the delay scales with the requested "
                    "sleep duration, which rules out ordinary network/server jitter and is "
                    "strong evidence this input reaches a SQL query unsafely, even with no "
                    "visible error.",
                    "Use parameterized queries / prepared statements, never build SQL from "
                    "input. The fact this responds to a blind payload with no visible error "
                    "means hiding database errors from users is not, on its own, protecting "
                    "you here.")
        return None
