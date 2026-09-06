"""Passive disclosure checks: error pages and directory listings — RF-01, RF-02, RNF-05."""

from __future__ import annotations

from tests.support import make_context, make_page
from webvigil.checks.disclosure.errors import ErrorPageCheck
from webvigil.checks.disclosure.listing import DirectoryListingCheck
from webvigil.core.findings import Category, Confidence, Severity

_WERKZEUG = (
    "<title>X // Werkzeug Debugger</title>Traceback (most recent call last): File &quot;a&quot;"
)
_TRACE = 'Traceback (most recent call last):\n  File "/app/x.py", line 1, in <module>'
_INDEX = '<title>Index of /uploads</title><h1>Index of /uploads</h1><a href="s.sql">s.sql</a>'
_CLEAN = "<html><body><h1>Welcome</h1><a href='/about'>about</a></body></html>"


async def test_error_page_check_flags_the_interactive_debugger_as_high() -> None:
    ctx = make_context(make_page(url="https://t.example/boom", text=_WERKZEUG))
    findings = await ErrorPageCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].check_id == "disclosure.debug.error-page"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].confidence is Confidence.HIGH
    assert "debugger" in findings[0].title.lower()


async def test_error_page_check_flags_a_plain_trace_as_medium() -> None:
    ctx = make_context(make_page(text=_TRACE))
    findings = await ErrorPageCheck().run(ctx)
    assert findings and findings[0].severity is Severity.MEDIUM


async def test_error_page_check_dedupes_per_framework_across_pages() -> None:
    pages = [
        make_page(url="https://t.example/a", text=_TRACE),
        make_page(url="https://t.example/b", text=_TRACE),
    ]
    ctx = make_context(pages[0], pages=pages)
    findings = await ErrorPageCheck().run(ctx)
    assert len(findings) == 1


async def test_error_page_check_is_quiet_on_a_generic_page() -> None:
    ctx = make_context(make_page(text=_CLEAN))
    assert await ErrorPageCheck().run(ctx) == []


async def test_directory_listing_check_reports_one_per_url() -> None:
    ctx = make_context(make_page(url="https://t.example/uploads/", text=_INDEX))
    findings = await DirectoryListingCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].check_id == "disclosure.listing.directory-index"
    assert findings[0].severity is Severity.MEDIUM
    assert "/uploads/" in findings[0].title
    assert "s.sql" in findings[0].evidence[0].content


async def test_directory_listing_check_is_quiet_on_a_normal_page() -> None:
    ctx = make_context(make_page(text=_CLEAN))
    assert await DirectoryListingCheck().run(ctx) == []


def test_both_checks_are_registered_under_disclosure() -> None:
    assert ErrorPageCheck.category is Category.DISCLOSURE
    assert DirectoryListingCheck.category is Category.DISCLOSURE
