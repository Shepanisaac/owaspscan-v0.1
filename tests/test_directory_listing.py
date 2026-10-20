import httpx

from conftest import HTML
from owaspscan.checks.base import REGISTRY
from owaspscan.checks.directory_listing import DirectoryListingCheck
from owaspscan.models import Severity


def page(body):
    return lambda request: httpx.Response(200, headers=HTML, text=body)


def test_is_passive():
    assert REGISTRY["directory-listing"].active is False


def test_apache_style_listing_flagged(make_ctx):
    body = ("<html><head><title>Index of /uploads</title></head><body>"
            "<h1>Index of /uploads</h1><a href='../'>Parent Directory</a></body></html>")
    ctx = make_ctx(page(body))
    found = DirectoryListingCheck().run(ctx)
    assert len(found) == 1 and found[0].severity == Severity.MEDIUM
    assert "Parent Directory" in found[0].evidence


def test_listing_without_parent_directory_link_still_flagged(make_ctx):
    body = "<html><head><title>Index of /backups</title></head><body></body></html>"
    ctx = make_ctx(page(body))
    found = DirectoryListingCheck().run(ctx)
    assert len(found) == 1
    assert "Parent Directory" not in found[0].evidence


def test_ordinary_page_never_flagged(make_ctx):
    body = "<html><head><title>Welcome</title></head><body><h1>Hello</h1></body></html>"
    ctx = make_ctx(page(body))
    assert DirectoryListingCheck().run(ctx) == []


def test_page_mentioning_index_in_prose_not_flagged(make_ctx):
    body = "<html><head><title>Site Index</title></head><body><p>Index of our pages</p></body></html>"
    ctx = make_ctx(page(body))
    assert DirectoryListingCheck().run(ctx) == []


def test_non_html_response_ignored(make_ctx):
    ctx = make_ctx(lambda r: httpx.Response(
        200, headers={"content-type": "application/json"}, text='{"ok": true}'))
    assert DirectoryListingCheck().run(ctx) == []
