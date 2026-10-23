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
`--cookie NAME=VALUE` (repeatable, for authenticated scans), `--header "NAME: VALUE"`
(repeatable, e.g. `--header "Authorization: Bearer <token>"` for apps that use a bearer
token instead of a cookie), `--checks id1,id2` (default: all), `--json PATH`, `--active`,
`--max-probes N` (default 150).

**Passive mode (default):** only normal GET page loads, plus a handful of fixed
sensitive-path requests (`exposed-files`). Safe against any site you're authorized to scan.

**Active mode (`--active`):** also runs `cors`, `reflection`, `sqli-errors`,
`open-redirect`, `access-control`, `ssrf`, `http-methods`, `crlf-injection`, `sqli-blind`,
`path-traversal`, `host-header` and `ssti`, which send GET (or, for `http-methods` only,
`OPTIONS`/`TRACE`) requests with harmless test values into parameters, headers, forms and
the landing page to look for misconfigurations. Get written authorization before using
`--active` against a site you don't operate yourself. **`sqli-blind` is more invasive than
the rest** — see its own note below before relying on it against anything you don't
operate yourself.

## Checks
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
| components | A06 | passive | Known-vulnerable or end-of-life library/platform versions |
| sri | A08 | passive | Cross-origin script/stylesheet tags with no Subresource Integrity check |
| ssrf | A10 | active | Parameters that may make the server itself fetch an attacker-chosen URL |
| http-methods | A05 | active | TRACE enabled (XST risk); dangerous methods advertised via OPTIONS |
| cache-control | A05 | passive | Login/password page served without Cache-Control: no-store |
| directory-listing | A05 | passive | Apache/nginx autoindex directory listing exposed |
| crlf-injection | A03 | active | Parameter value whose CR/LF characters survive into a response header |
| sqli-blind | A03 | active | Time-based blind SQL injection via sleep payloads (two-stage confirmed) |
| path-traversal | A01 | active | Path traversal / LFI via a file- or path-shaped parameter |
| host-header | A05 | active | Host/X-Forwarded-Host header trusted and echoed into redirects or pages |
| ssti | A03 | active | Server-side template injection (payload arithmetic evaluated by the server) |

Active checks only run with `--active` and only send GET requests, through a shared,
delayed, capped probe budget (`--max-probes`, default 150). A plain `owaspscan <url>
--i-have-permission` always stays passive.

**`access-control` needs `--cookie` and/or `--header`** (your own session) to mean
anything — it compares pages fetched with those credentials against the same URLs
fetched with neither. It only proves a page needs *no* authentication; it cannot detect
one user reaching another user's data (true IDOR), which needs a second account's
credentials and is out of scope here. If most of the authenticated crawl comes back
401/403, it reports that your cookie/token is likely invalid or expired instead of
running the (meaningless) comparison.

**`session` also inspects an `Authorization: Bearer` token** supplied via `--header`. For
a token that parses as a JWT (three base64url-encoded, dot-separated segments), it reads
the header and payload — never the signature, no key is needed or implied to be checked —
and flags `"alg": "none"` (some libraries will accept an unsigned token outright) and a
missing `exp` claim (the token may never expire). A non-JWT bearer token instead gets the
same short/numeric/repetitive heuristic as a cookie.

**`ssrf` is a heuristic, not a confirmed exploit.** Without a public callback server to
receive an out-of-band request, there's no way to be fully certain a target application
actually reached out anywhere — it only has two signals to go on: cloud-metadata-shaped
content appearing in the response body (reported as HIGH, strong evidence), or the
response taking noticeably longer than a control request to an ordinary URL (reported as
INFO, explicitly labeled "unconfirmed" in the finding — worth checking by hand, not proof).
Redirect responses are skipped entirely, since a 3xx bounce is the browser following a
link, not the server fetching anything — that's `open-redirect`'s job, not `ssrf`'s.

**`http-methods` only tests the landing page**, not every crawled page — method support is
a server/vhost configuration question, not a per-page one, so testing further pages would
just spend probe budget for no extra signal. Its `OPTIONS` finding is advisory only: the
`Allow`/`Access-Control-Allow-Methods` header says what the server is configured to route
to, not that `PUT`/`DELETE`/`CONNECT` actually succeed without authentication — verify
manually. Its `TRACE` finding is a direct observation (the server answered a live `TRACE`
request with HTTP 200), so it's reported at MEDIUM rather than advisory.

**`cache-control` only recognizes a password field as "sensitive.**" It cannot know that
an account dashboard or order-history page is sensitive without a cookie/header to compare
against — that's a real detection gap, not a clean bill of health, for any authenticated
page that isn't the login form itself.

**`directory-listing` only recognizes the standard Apache/nginx autoindex markup** (an
"Index of ..." title/heading). A themed or custom directory-listing page will not be
recognized.

**`crlf-injection` is a confirmed finding, not a heuristic** — the marker header can only
appear in the response if raw CR/LF characters from the parameter actually reached code
building a response header, so there's no ambiguity the way there is with `ssrf`'s timing
signal.

**`sqli-blind` actually makes the target database pause**, unlike every other check here,
so it carries extra safety limits beyond the normal `--max-probes` cap: only the first 5
parameters found are tested at all; each one gets a short (1s) exploratory sleep payload,
and only a timing gap there triggers a second, longer (3s) confirmation payload to rule out
ordinary jitter, rather than firing a long sleep at every parameter blind; and there's an
extra pause before every sleep-payload probe on top of the normal `--delay`, specifically
to avoid stacking load on a database that just paused. It stops at the first of
MySQL/PostgreSQL/SQL Server whose payload shows a signal for a given parameter rather than
trying all three. Expect a scan with `sqli-blind` enabled to take noticeably longer than
one without it, and consider `--checks` to exclude it if you want a faster pass.

**`path-traversal` only tries two fixed payloads per candidate parameter** (an 8-level-deep
Unix path targeting `/etc/passwd`, and a Windows path targeting `win.ini`), and only against
parameters whose *name* looks file/path-shaped. A traversal bug behind a parameter named
something unrelated, or one that needs a different depth or encoding to clear the app's own
path handling, won't be found. Like `crlf-injection`, a finding here is confirmed, not a
heuristic — the marker content checked for can only appear if the file was actually read.

**`host-header` only tests the landing page** (like `http-methods`, this is a server/app
config question, not a per-page one) and only recognizes reflection it can see in a GET
response or redirect. The real-world impact of this bug is usually in a flow this tool
can't observe at all — a password-reset email built with the attacker's hostname — so a
finding here means the ingredients for that attack exist, not that it's been demonstrated.

**`ssti` only tries three template syntaxes** (Jinja2/Twig/Nunjucks-style `{{ }}`,
Freemarker/JSP-EL-style `${ }`, ERB-style `<%= %>`), covering the most common engines
without trying every one that exists — a less common engine's own syntax (Smarty, Velocity,
Pug/Jade) won't be tried. Like `crlf-injection` and `path-traversal`, a finding here is
confirmed, not a heuristic: the random two-prime product checked for can only appear
without the template syntax around it if the server actually evaluated the expression.

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

`components` only catches a library or platform when its version is visible somewhere
(a script/stylesheet filename, a generator meta tag, a Server/X-Powered-By header). A
modern bundled frontend (Webpack, Vite) that inlines its dependencies with no version
string anywhere will show nothing — that is a detection gap, not a clean bill of health.
The signature list is small and curated, not a live CVE feed; it will miss anything not
in its table.

## `--header` support: a real gap to know about
`--header`/bearer-token support is unit- and mock-tested, and I validated it end-to-end
against a local mock server (including the stale-credential path), but **it has not yet
been run against a real, live bearer-token-authenticated site** — both sites this tool has
actually been tested against use PHP session cookies, not bearer tokens. Treat it as a new,
less battle-tested feature until it's been proven on a real target.

## OWASP Top 10 (2021) coverage
This tool has at least one check in 8 of the 10 categories: A01, A02, A03, A05, A06, A07,
A08, A10. A04 (Insecure Design) and A09 (Logging/Monitoring) are not checked — they
describe how a system is architected and operated, not something visible from the outside
in HTTP responses. Within the categories it does cover, coverage is partial and in some
cases thin: A03, for example, covers reflected XSS, error-based SQL injection, time-based
blind SQL injection, and CR/LF header injection — but not stored/DOM-based XSS, or other
injection types (command, NoSQL, XXE). A08 is SRI only — it says nothing about CI/CD pipeline integrity, unsigned
software updates, or insecure deserialization. A10 (`ssrf`) is a response-based heuristic
with no out-of-band canary, so it will miss any SSRF that doesn't leak metadata content or
cause a measurable timing difference — see the `ssrf` note above.

## Tests
    pytest
