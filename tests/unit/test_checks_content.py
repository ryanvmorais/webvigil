"""
``content.sri.missing`` and ``content.mixed`` — spec 013 RF-11, RF-12.

Pure over synthetic pages: :func:`make_page` supplies the HTML,
:func:`make_context` wraps it, and no HTTP is issued. ``content.mixed`` is
exercised against a synthesized ``https://`` page because the fixture app is
served over ``http://`` (design Resolved decision 10).
"""

from __future__ import annotations

from tests.support import make_context, make_page
from webvigil.checks.content.checks import MixedContentCheck, SriMissingCheck
from webvigil.core.findings import Category, ScanMode, Severity


async def _sri(html: str, *, url: str = "https://shop.example/") -> list[str]:
    """
    Args:
        html (str): The page body.
        url (str): The page URL. Defaults to an HTTPS shop page.

    Returns:
        list[str]: The finding titles ``SriMissingCheck`` produces.
    """
    ctx = make_context(make_page(url=url, text=html))
    return [f.title for f in await SriMissingCheck().run(ctx)]


async def _mixed(html: str, *, url: str = "https://shop.example/") -> list[tuple[str, Severity]]:
    """
    Args:
        html (str): The page body.
        url (str): The page URL. Defaults to an HTTPS shop page.

    Returns:
        list[tuple[str, Severity]]: ``(title, severity)`` per ``content.mixed``
            finding.
    """
    ctx = make_context(make_page(url=url, text=html))
    return [(f.title, f.severity) for f in await MixedContentCheck().run(ctx)]


# ---------------------------------------------------------------------------
# content.sri.missing
# ---------------------------------------------------------------------------


def test_sri_check_metadata() -> None:
    """The check is passive, ``Category.CONTENT``, and carries the SRI CWEs."""
    assert SriMissingCheck.category is Category.CONTENT
    assert SriMissingCheck.mode is ScanMode.PASSIVE
    assert set(SriMissingCheck.cwe) == {353, 1104}


async def test_cross_origin_script_without_integrity_is_flagged() -> None:
    """A CDN ``<script>`` with no ``integrity`` produces one MEDIUM finding."""
    titles = await _sri('<script src="https://cdn.other/lib.js"></script>')
    expected = (
        "Cross-origin resource loaded without Subresource Integrity: https://cdn.other/lib.js"
    )
    assert titles == [expected]


async def test_integrity_without_crossorigin_is_flagged_distinctly() -> None:
    """``integrity`` but no ``crossorigin`` is a separate, still-MEDIUM finding."""
    titles = await _sri(
        '<link rel="stylesheet" href="https://cdn.other/a.css" integrity="sha384-x">'
    )
    expected = "Subresource Integrity present but 'crossorigin' missing: https://cdn.other/a.css"
    assert titles == [expected]


async def test_same_origin_and_fully_protected_resources_are_not_flagged() -> None:
    """A same-origin script and a fully-attributed cross-origin one produce nothing."""
    html = (
        '<script src="/app.js"></script>'
        '<script src="https://cdn.other/ok.js" integrity="sha384-x" crossorigin="anonymous">'
        "</script>"
    )
    assert await _sri(html) == []


async def test_the_same_cdn_resource_on_two_pages_is_one_finding() -> None:
    """A CDN script linked from two crawled pages collapses to a single finding."""
    tag = '<script src="https://cdn.other/x.js"></script>'
    page_a = make_page(url="https://shop.example/a", text=tag)
    page_b = make_page(url="https://shop.example/b", text=tag)
    ctx = make_context(page_a, pages=[page_a, page_b])
    assert len(await SriMissingCheck().run(ctx)) == 1


# ---------------------------------------------------------------------------
# content.mixed
# ---------------------------------------------------------------------------


async def test_active_and_passive_mixed_content_are_graded() -> None:
    """An ``http://`` script is MEDIUM; an ``http://`` image is LOW."""
    html = '<script src="http://cdn.other/x.js"></script><img src="http://cdn.other/p.png">'
    found = dict(await _mixed(html))
    assert found["Active mixed content: <script> loads http://cdn.other/x.js over HTTP"] == (
        Severity.MEDIUM
    )
    assert found["Passive mixed content: <img> loads http://cdn.other/p.png over HTTP"] == (
        Severity.LOW
    )


async def test_protocol_relative_url_is_not_mixed_content() -> None:
    """A ``//host`` subresource inherits the page scheme and is not flagged."""
    assert await _mixed('<script src="//cdn.other/x.js"></script>') == []


async def test_an_http_served_page_is_skipped() -> None:
    """A page served over HTTP has nothing to downgrade, so the check does not run."""
    html = '<script src="http://cdn.other/x.js"></script>'
    assert await _mixed(html, url="http://shop.example/") == []
