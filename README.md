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

## v0.1 checks
security-headers, cookies, transport, disclosure, exposed-files (all passive, GET-only).

## Adding a check
Create `src/owaspscan/checks/yourcheck.py`, subclass `Check`, decorate with `@register`,
and import it in `checks/__init__.py`. Add a test with a mocked transport.

## Tests
    pytest
