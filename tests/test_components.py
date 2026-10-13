import httpx

from conftest import HTML
from owaspscan.checks.base import REGISTRY
from owaspscan.checks.components import ComponentsCheck, is_vulnerable, parse_version
from owaspscan.models import Severity


def titles(found):
    return {f.title for f in found}


def page(body, headers=None):
    return lambda request: httpx.Response(200, headers={**HTML, **(headers or {})}, text=body)


def test_is_passive():
    assert REGISTRY["components"].active is False


# ---------- unit: version parsing / comparison ----------

def test_parse_version_valid():
    assert parse_version("3.2.1") == (3, 2, 1)
    assert parse_version("1.9") == (1, 9)


def test_parse_version_rejects_garbage():
    assert parse_version("latest") is None
    assert parse_version("abc123") is None
    assert parse_version("3.2.1-beta") is None


def test_is_vulnerable_handles_different_lengths():
    assert is_vulnerable((3, 2), (3, 2, 1)) is True   # 3.2.0 < 3.2.1
    assert is_vulnerable((3, 2, 1), (3, 2)) is False  # 3.2.1 >= 3.2.0
    assert is_vulnerable((5, 0, 0), None) is True      # no safe floor tracked


# ---------- vulnerable library detection ----------

def test_outdated_jquery_script_tag_flagged(make_ctx):
    body = '<script src="/js/jquery-1.12.4.min.js"></script>'
    ctx = make_ctx(page(body))
    found = ComponentsCheck().run(ctx)
    assert len(found) == 1
    assert "jQuery" in found[0].title and found[0].severity == Severity.MEDIUM
    assert "CVE-2020-11022" in found[0].evidence


def test_patched_jquery_is_clean(make_ctx):
    body = '<script src="/js/jquery-3.6.0.min.js"></script>'
    ctx = make_ctx(page(body))
    assert ComponentsCheck().run(ctx) == []


def test_cdn_hosted_library_still_detected(make_ctx):
    body = '<script src="https://cdn.jsdelivr.net/npm/jquery@1.12.4/dist/jquery.min.js"></script>'
    ctx = make_ctx(page(body))
    found = ComponentsCheck().run(ctx)
    assert len(found) == 1 and "jQuery" in found[0].title


def test_version_in_link_href_also_checked(make_ctx):
    body = '<link rel="stylesheet" href="/css/bootstrap-3.3.7.min.css">'
    ctx = make_ctx(page(body))
    found = ComponentsCheck().run(ctx)
    assert len(found) == 1 and "Bootstrap" in found[0].title


def test_oldest_matching_rule_wins_highest_severity(make_ctx):
    # jQuery 1.8.0 falls under both the 3.5.0 MEDIUM rule and the 1.9.0 LOW rule;
    # it must be reported once, at the higher severity
    body = '<script src="/js/jquery-1.8.0.min.js"></script>'
    ctx = make_ctx(page(body))
    found = ComponentsCheck().run(ctx)
    assert len(found) == 1 and found[0].severity == Severity.MEDIUM


# ---------- filenames must not cross-match each other ----------

def test_jquery_ui_filename_not_misread_as_plain_jquery(make_ctx):
    body = '<script src="/js/jquery-ui-1.11.4.min.js"></script>'
    ctx = make_ctx(page(body))
    found = ComponentsCheck().run(ctx)
    assert titles(found) == {"Outdated component: jQuery UI"}


def test_jquery_migrate_filename_detected_on_its_own(make_ctx):
    body = '<script src="/js/jquery.migrate-3.0.0.min.js"></script>'
    ctx = make_ctx(page(body))
    found = ComponentsCheck().run(ctx)
    assert titles(found) == {"Outdated component: jQuery Migrate"}


def test_unrelated_filename_is_ignored(make_ctx):
    body = '<script src="/js/app.bundle.min.js"></script>'
    ctx = make_ctx(page(body))
    assert ComponentsCheck().run(ctx) == []


def test_version_missing_from_filename_is_skipped(make_ctx):
    body = '<script src="/js/jquery.min.js"></script>'
    ctx = make_ctx(page(body))
    assert ComponentsCheck().run(ctx) == []


def test_unparseable_version_suffix_is_skipped(make_ctx):
    body = '<script src="/js/jquery-latest.min.js"></script>'
    ctx = make_ctx(page(body))
    assert ComponentsCheck().run(ctx) == []


# ---------- platform detection: generator tag and headers ----------

def test_wordpress_generator_tag_flagged(make_ctx):
    body = '<meta name="generator" content="WordPress 5.4.2">'
    ctx = make_ctx(page(body))
    found = ComponentsCheck().run(ctx)
    assert len(found) == 1 and "WordPress" in found[0].title


def test_current_wordpress_is_clean(make_ctx):
    body = '<meta name="generator" content="WordPress 6.4.1">'
    ctx = make_ctx(page(body))
    assert ComponentsCheck().run(ctx) == []


def test_eol_php_header_flagged(make_ctx):
    ctx = make_ctx(page("<p>x</p>", headers={"X-Powered-By": "PHP/7.2.3"}))
    found = ComponentsCheck().run(ctx)
    assert len(found) == 1 and "PHP" in found[0].title and found[0].severity == Severity.LOW


def test_vulnerable_apache_header_flagged(make_ctx):
    ctx = make_ctx(page("<p>x</p>", headers={"Server": "Apache/2.4.49"}))
    found = ComponentsCheck().run(ctx)
    assert len(found) == 1 and found[0].severity == Severity.HIGH


def test_cloudflare_server_header_is_clean(make_ctx):
    # the common case on CDN-fronted sites: no version at all, must not crash or false-flag
    ctx = make_ctx(page("<p>x</p>", headers={"Server": "cloudflare"}))
    assert ComponentsCheck().run(ctx) == []


# ---------- dedup across pages ----------

def test_same_library_on_multiple_pages_reported_once(make_ctx):
    def handler(request):
        body = '<script src="/js/jquery-1.12.4.min.js"></script><a href="/other">x</a>'
        return httpx.Response(200, headers=HTML, text=body)
    ctx = make_ctx(handler)
    found = ComponentsCheck().run(ctx)
    assert len(found) == 1


def test_no_components_present_is_clean(make_ctx):
    ctx = make_ctx(page("<p>a plain page with no scripts</p>"))
    assert ComponentsCheck().run(ctx) == []
