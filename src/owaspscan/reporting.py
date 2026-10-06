"""Console and JSON output."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .engine import ScanResult
from .models import CATEGORIES, Severity


def summarize(result: ScanResult) -> dict[str, int]:
    counts = Counter(f.severity.name for f in result.findings)
    return {s.name: counts.get(s.name, 0) for s in sorted(Severity, reverse=True)}


def render_console(result: ScanResult) -> str:
    lines = [
        f"owaspscan {__version__} | {result.target}",
        f"Scanned {result.pages_scanned} page(s), {len(result.findings)} finding(s)",
        "  ".join(f"{name}: {n}" for name, n in summarize(result).items()),
        "",
    ]
    for f in result.findings:
        lines += [
            f"[{f.severity.name}] {f.category} {CATEGORIES.get(f.category, '')}: {f.title}",
            f"    url:      {f.url}",
            f"    evidence: {f.evidence}",
            f"    fix:      {f.remediation}",
            "",
        ]
    return "\n".join(lines)


def write_json(result: ScanResult, path: str) -> None:
    report = {
        "tool": "owaspscan",
        "version": __version__,
        "target": result.target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pages_scanned": result.pages_scanned,
        "summary": summarize(result),
        "findings": [f.to_dict() for f in result.findings],
    }
    Path(path).write_text(json.dumps(report, indent=2), encoding="utf-8")
