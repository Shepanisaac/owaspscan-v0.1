# owaspscan

A small, extensible command-line scanner that checks a web application for common
OWASP Top 10 weaknesses. **Only scan systems you own or have written permission to test.**

## Install
    pip install -e ".[dev]"

Requires Python 3.10+.

## Usage
    owaspscan https://target.example --i-have-permission
    owaspscan http://localhost:3000 --i-have-permission --json report.json
    owaspscan https://target.example --i-have-permission --active --max-probes 150
    owaspscan --checks tls,security-headers https://target.example --i-have-permission
    owaspscan --list-checks

Options: `--max-pages` (default 25), `--delay` (default 0.2s), `--timeout` (default 10s),
`--cookie NAME=VALUE` (repeatable, for authenticated scans), `--checks id1,id2`
(default: all), `--json PATH`, `--active`, `--max-probes N` (default 150).

**Passive mode (default):** only normal GET page loads, plus a handful of fixed
sensitive-path requests (`exposed-files`). Safe against any site you're authorized to scan.

**Active mode (`--active`):** also runs `cors`, `reflection`, `sqli-errors` and
`open-redirect`, which send GET requests with harmless test values into parameters and
forms to look for misconfigurations. Get written authorization before using `--active`
against a site you don't operate yourself.

## v0.2 checks
| Check | Category | Mode | Detects |
|---|---|---|---|
| security-headers | A05 | passive | Missing CSP, HSTS, clickjacking and nosniff protections |
| cookies | A07 | passive | Cookies missing Secure, HttpOnly or SameSite |
| transport | A02 | passive | Site served over plain HTTP |
| disclosure | A05 | passive | Server/framework version leaks in headers |
| exposed-files | A05 | passive | `.git`, `.env`, backups, debug pages left public |
| tls | A02 | passive | Legacy TLS 1.0/1.1 support, certificate problems |
| cors | A05 | active | CORS trusting arbitrary, null or look-alike origins |
| reflection | A03 | active | Reflected input not escaped for its context (possible XSS) |
| sqli-errors | A03 | active | Database error messages triggered by a quote |
| open-redirect | A01 | active | Parameter-controlled redirect to an external site |
| session | A07 | passive | Weak-looking session cookie (short, numeric, repeated runs) |
| csrf | A01 | passive | State-changing forms with no CSRF token field and no SameSite cookie |
| access-control | A01 | active | Pages reachable while logged in that need no auth at all |

Active checks only run with `--active` and only send GET requests, through a shared,
delayed, capped probe budget (`--max-probes`, default 150). A plain `owaspscan <url>
--i-have-permission` always stays passive.

**`access-control` needs `--cookie`** (your own session) to mean anything — it compares
pages fetched with that cookie against the same URLs fetched with no cookie at all. It
only proves a page needs *no* authentication; it cannot detect one user reaching another
user's data (true IDOR), which needs a second account's cookie and is out of scope here.

## Adding a check
Create `src/owaspscan/checks/yourcheck.py`, subclass `Check`, decorate with `@register`,
and import it in `checks/__init__.py`. Add a test with a mocked transport.

## Limitations
`access-control` is a single-identity check: it flags pages open to anyone, not pages one logged-in user can read that belong to another user (IDOR). That needs two accounts and is not implemented.

This is a passive-leaning scanner. It detects common misconfigurations and error-based
signals well, but it does **not** cover: business-logic flaws, broken access control
between user accounts (IDOR), authentication/session weaknesses, blind or second-order
SQL injection, stored/DOM-based XSS, POST-only forms and JSON APIs, or anything requiring
a logged-in multi-step workflow. A clean report is not proof the application is secure —
treat it as a first pass, not a replacement for manual testing.

## Tests
    pytest
