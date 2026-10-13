"""Known-vulnerable version ranges for a small, curated set of widely-used components.

This is intentionally short. Each entry names a real, well-documented issue rather than
trying to be an exhaustive CVE database. `max_safe` is the first version considered safe
(exclusive upper bound on the vulnerable range); `None` means "any version below is
unsafe, no known safe floor tracked here." `generic` entries (no CVE) represent
end-of-life/stale-version hygiene rather than a specific exploit.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Signature:
    name: str
    max_safe: tuple[int, ...] | None  # first safe version; versions below this are flagged
    severity: str  # "HIGH" | "MEDIUM" | "LOW" | "INFO"
    summary: str
    cve: str | None = None


# Matched against filenames like "jquery-1.12.4.min.js" or "bootstrap-3.3.7.min.css",
# and against version strings pulled from headers / generator meta tags.
LIBRARIES: dict[str, tuple[Signature, ...]] = {
    "jquery": (
        Signature("jQuery", (3, 5, 0), "MEDIUM",
                   "jQuery before 3.5.0 is vulnerable to XSS via jQuery.htmlPrefilter() "
                   "when passing untrusted HTML strings to .html()/.append()/etc.",
                   cve="CVE-2020-11022 / CVE-2020-11023"),
        Signature("jQuery", (1, 9, 0), "LOW",
                   "jQuery before 1.9.0 has additional, older cross-site scripting issues "
                   "in its HTML parsing.", cve="CVE-2012-6708"),
    ),
    "jquery-ui": (
        Signature("jQuery UI", (1, 13, 0), "MEDIUM",
                   "jQuery UI before 1.13.0 is vulnerable to XSS via the closeText option "
                   "of the Datepicker widget.", cve="CVE-2021-41182"),
    ),
    "jquery.migrate": (
        Signature("jQuery Migrate", (3, 4, 0), "LOW",
                   "Older jQuery Migrate releases forward jQuery's own pre-3.5.0 "
                   "htmlPrefilter XSS behaviour.", cve="CVE-2020-11023"),
    ),
    "bootstrap": (
        Signature("Bootstrap", (4, 3, 1), "MEDIUM",
                   "Bootstrap before 4.3.1 is vulnerable to XSS via the data-template, "
                   "data-content or data-title attributes of tooltip/popover plugins.",
                   cve="CVE-2019-8331"),
    ),
    "angular": (
        Signature("AngularJS", (1, 8, 0), "MEDIUM",
                   "AngularJS before 1.8.0 has known sandbox-bypass XSS issues; the 1.x "
                   "line as a whole is past its end-of-life support window.",
                   cve="CVE-2020-7676"),
    ),
    "lodash": (
        Signature("Lodash", (4, 17, 12), "HIGH",
                   "Lodash before 4.17.12 is vulnerable to prototype pollution via "
                   "defaultsDeep, merge and other deep-set functions.",
                   cve="CVE-2019-10744"),
    ),
    "moment": (
        Signature("Moment.js", (2, 29, 4), "LOW",
                   "Moment.js before 2.29.4 is vulnerable to ReDoS (catastrophic "
                   "backtracking) when parsing certain crafted date strings.",
                   cve="CVE-2022-31129"),
    ),
}

# Matched against a generator meta tag or an X-Powered-By / Server-style header value.
PLATFORMS: dict[str, tuple[Signature, ...]] = {
    "wordpress": (
        Signature("WordPress", (5, 8, 0), "MEDIUM",
                   "This WordPress version is below 5.8 and predates several security "
                   "releases; core and bundled plugins should be updated.",
                   cve=None),
    ),
    "php": (
        Signature("PHP", (7, 4, 0), "LOW",
                   "This PHP major/minor version has reached end-of-life and no longer "
                   "receives security patches.", cve=None),
    ),
    "apache": (
        Signature("Apache HTTP Server", (2, 4, 50), "HIGH",
                   "Apache HTTP Server 2.4.49 has a path traversal / remote code "
                   "execution flaw when certain configurations are in use.",
                   cve="CVE-2021-41773"),
    ),
}
