# owaspscan

A small, extensible command-line scanner that checks a web application for common
OWASP Top 10 weaknesses. **Only scan systems you own or have written permission to test.**

## Install
    pip install -e ".[dev]"

## Usage
    owaspscan https://target.example --i-have-permission
    owaspscan http://localhost:3000 --i-have-permission --json report.json
    owaspscan --list-checks

Options: `--max-pages`, `--delay`, `--timeout`, `--cookie NAME=VALUE` (repeatable),
`--checks id1,id2`, `--json PATH`.

**Active mode:** `--active` enables checks that send harmless test probes (GET only).
It is off by default, so a normal scan stays passive. `--max-probes N` caps the extra
requests (default 100). `owaspscan --list-checks` shows which checks are active.

## v0.1 checks
Passive: security-headers, cookies, transport, disclosure, exposed-files, tls.
Active (need `--active`): cors.

## Adding a check
Create `src/owaspscan/checks/yourcheck.py`, subclass `Check`, decorate with `@register`,
and import it in `checks/__init__.py`. Add a test with a mocked transport.

## Tests
    pytest
