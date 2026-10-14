import httpx

from conftest import HTML
from owaspscan.cli import main
from owaspscan.config import ScanConfig
from owaspscan.crawler import crawl
from owaspscan.engine import run_scan


def test_crawler_stays_in_scope_and_skips_logout():
    requested = []

    def handler(request):
        requested.append(str(request.url))
        body = ('<a href="/a">a</a><a href="https://other.test/x">x</a>'
                '<a href="/logout">out</a>')
        return httpx.Response(200, headers=HTML, text=body)

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    pages = crawl(client, ScanConfig(target="https://example.test/", delay=0))
    assert {p.url for p in pages} == {"https://example.test/", "https://example.test/a"}
    assert not any("other.test" in u or "logout" in u for u in requested)


def test_crawler_respects_max_pages():
    handler = lambda r: httpx.Response(200, headers=HTML, text='<a href="/1">1</a><a href="/2">2</a>')
    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = ScanConfig(target="https://example.test/", delay=0, max_pages=2)
    assert len(crawl(client, config)) == 2


def test_full_scan_sorted_by_severity():
    def handler(request):
        if request.url.path == "/.env":
            return httpx.Response(200, headers={"content-type": "text/plain"}, text="SECRET=1")
        return httpx.Response(200, headers={**HTML, "Server": "Apache/2.4.1"}, text="<html></html>")

    result = run_scan(ScanConfig(target="https://example.test/", delay=0),
                      transport=httpx.MockTransport(handler))
    severities = [f.severity for f in result.findings]
    assert severities == sorted(severities, reverse=True)
    assert any(f.title == "Environment file exposed" for f in result.findings)


def test_unknown_check_rejected():
    import pytest
    with pytest.raises(ValueError):
        run_scan(ScanConfig(target="https://example.test/", enabled_checks=["nope"]))


def test_cli_requires_permission(capsys):
    assert main(["https://example.test"]) == 2
    assert "--i-have-permission" in capsys.readouterr().err


def test_cli_rejects_bad_url():
    assert main(["example.test", "--i-have-permission"]) == 2


def test_cli_list_checks(capsys):
    assert main(["--list-checks"]) == 0
    assert "security-headers" in capsys.readouterr().out


def test_header_flag_parsed(capsys):
    from owaspscan.cli import build_parser
    args = build_parser().parse_args(
        ["https://x.test", "--header", "Authorization: Bearer xyz", "--header", "X-Api-Key:123"])
    assert args.header == ["Authorization: Bearer xyz", "X-Api-Key:123"]


def test_cli_rejects_malformed_header():
    assert main(["https://example.test", "--i-have-permission", "--header", "no-colon-here"]) == 2


def test_cli_rejects_empty_header_name():
    assert main(["https://example.test", "--i-have-permission", "--header", ":value"]) == 2


def test_header_with_colon_in_value_is_split_on_first_colon():
    # e.g. a header value that is itself a URL, "Referer: https://example.com"
    from owaspscan.cli import build_parser
    args = build_parser().parse_args(
        ["https://x.test", "--header", "Referer: https://example.com"])
    name, sep, value = args.header[0].partition(":")
    assert name == "Referer" and value.lstrip() == "https://example.com"
