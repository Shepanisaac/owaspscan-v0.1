"""A01: pages reachable while logged in that are equally reachable WITHOUT the session
cookie or auth header (active, GET only). This is a single-identity check: it proves a
page needs no authentication at all. It cannot prove IDOR between two different users'
data — that needs a second account's credentials, which this check does not use.
"""
from __future__ import annotations

import re
import time
from urllib.parse import urlsplit

import httpx

from ..models import Finding, Severity
from .base import Check, ScanContext, register

ID_LIKE = re.compile(r"/\d{2,}(?:/|$)|[?&]\w*id\w*=\d{2,}|[0-9a-f]{8}-[0-9a-f]{4}-",
                      re.IGNORECASE)
LENGTH_RATIO_MIN = 0.85
LENGTH_RATIO_MAX = 1.15
AUTH_FAILURE_STATUSES = (401, 403)
AUTH_FAILURE_RATIO = 0.5  # if at least half the authenticated crawl got 401/403, the
                          # supplied cookie/token is probably invalid or expired — the
                          # comparison below would just be noise, so skip it and say why


def _path_and_query(url: str) -> str:
    """Only the part of the URL an application actually routes on — never the scheme or
    host, which can themselves contain digits (e.g. a numeric IP) and falsely look ID-like."""
    parts = urlsplit(url)
    return parts.path + ("?" + parts.query if parts.query else "")


def _similar(a: httpx.Response, b: httpx.Response) -> bool:
    """Cheap same-page heuristic: close in length and the same <title>, where present.
    Not exact equality, since timestamps/tokens make identical bytes unlikely even when
    it is genuinely the same page returned to both identities."""
    if a.status_code != b.status_code or a.status_code != 200:
        return False
    la, lb = len(a.text), len(b.text)
    if lb == 0 or not (LENGTH_RATIO_MIN <= la / lb <= LENGTH_RATIO_MAX):
        return False
    ta = re.search(r"<title>(.*?)</title>", a.text, re.IGNORECASE | re.DOTALL)
    tb = re.search(r"<title>(.*?)</title>", b.text, re.IGNORECASE | re.DOTALL)
    if ta and tb:
        return ta.group(1).strip() == tb.group(1).strip()
    return True  # no <title> to compare (e.g. JSON): length ratio alone decided it


@register
class AccessControlCheck(Check):
    id = "access-control"
    category = "A01"
    description = "Pages reachable while logged in that need no authentication at all"
    active = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.config.cookies and not ctx.config.headers:
            return []  # nothing to compare against: the crawl was already anonymous

        failed = sum(1 for p in ctx.pages if p.response.status_code in AUTH_FAILURE_STATUSES)
        if ctx.pages and failed / len(ctx.pages) >= AUTH_FAILURE_RATIO:
            return [self.finding(
                "Authenticated crawl mostly failed — cookie/token may be invalid or expired",
                Severity.INFO, ctx.landing.url,
                f"{failed} of {len(ctx.pages)} page(s) returned 401/403 even with the "
                "supplied credentials, so access-control results would not be meaningful.",
                "Log in again, get a fresh --cookie/--header value, and rerun.")]

        findings: list[Finding] = []
        # Deliberately a fresh client with none of config.cookies/config.headers: this is
        # the "logged out" identity the authenticated pages get compared against.
        with httpx.Client(timeout=ctx.config.timeout, follow_redirects=True,
                           headers={"User-Agent": ctx.config.user_agent},
                           transport=ctx.transport) as anon_client:
            for page in ctx.pages:
                if page is ctx.landing:
                    continue  # the entry point is almost always meant to be public
                if any(word in page.url.lower() for word in ctx.config.exclude):
                    continue
                if page.response.status_code != 200:
                    continue
                if ctx.probes_used >= ctx.config.max_probes:
                    break
                ctx.probes_used += 1
                time.sleep(ctx.config.delay)
                try:
                    anon = anon_client.get(page.url)
                except httpx.HTTPError:
                    continue
                if _similar(page.response, anon):
                    specific = bool(ID_LIKE.search(_path_and_query(page.url)))
                    findings.append(self.finding(
                        "Page accessible without authentication"
                        + (" (URL references a specific record)" if specific else ""),
                        Severity.HIGH if specific else Severity.LOW, page.url,
                        f"The same page (HTTP 200, similar content) was returned with and "
                        f"without the configured session cookie/auth header.",
                        "Require authentication server-side for this page/endpoint; "
                        "don't rely on the client not knowing the URL."))
        return findings
