"""
JavaScript-application detection — the warning for a crawl that ended at a client-rendered shell.

Pure functions over HTML strings and ``Page`` values: no HTTP. The shells are the real shapes
the frameworks emit (an empty ``<app-root>`` or ``<div id="root">`` plus a bundle); the negatives
are the pages that must never trigger the warning (content of their own, no scripts, data-only
scripts, a crawl that did find a surface).
"""

from __future__ import annotations

import httpx

from webvigil.core.context import Page
from webvigil.crawler.jsapp import looks_like_script_app, script_app_warning

_ANGULAR = (
    "<!doctype html><html><head><title>Shop</title><base href='/'>"
    "<link rel='stylesheet' href='styles.css'></head><body><app-root></app-root>"
    "<noscript>Please enable JavaScript to use this application, it will not work without it "
    "and there is nothing to read here when scripts are off.</noscript>"
    "<script src='runtime.js' type='module'></script><script src='main.js' type='module'></script>"
    "</body></html>"
)
_REACT = (
    "<html><body><div id='root'></div><script src='/static/js/bundle.js'></script></body></html>"
)
_ARTICLE = (
    "<html><body><h1>Release notes</h1><p>" + "A paragraph with real content. " * 12 + "</p>"
    "<script src='analytics.js'></script></body></html>"
)


def _page(html: str, *, content_type: str = "text/html", status: int = 200) -> Page:
    """
    Args:
        html (str): The response body.
        content_type (str): The ``Content-Type`` header. Defaults to ``text/html``.
        status (int): The HTTP status. Defaults to ``200``.

    Returns:
        Page: An entry page carrying ``html``.
    """
    return Page(
        requested_url="https://example.com/",
        url="https://example.com/",
        status_code=status,
        headers=httpx.Headers({"content-type": content_type}),
        text=html,
        elapsed_ms=1.0,
    )


def test_framework_shells_are_recognised() -> None:
    """An empty app root plus a bundle is a shell, whatever the framework calls the root."""
    assert looks_like_script_app(_ANGULAR)
    assert looks_like_script_app(_REACT)


def test_pages_with_content_of_their_own_are_not_shells() -> None:
    """A page that reads on its own is not a shell, even when it also loads a script."""
    assert not looks_like_script_app(_ARTICLE)


def test_a_sparse_page_without_scripts_is_not_a_shell() -> None:
    """Little text and no script is a small static page, not an application."""
    assert not looks_like_script_app("<html><body><p>Hello</p></body></html>")


def test_a_data_only_script_does_not_make_a_shell() -> None:
    """JSON-LD is data: a page whose only script is metadata does not run an application."""
    page = (
        '<html><head><script type=\'application/ld+json\'>{"@type": "WebSite"}</script></head>'
        "<body><p>Hi</p></body></html>"
    )
    assert not looks_like_script_app(page)


def test_a_shell_with_a_thin_crawl_is_warned_about() -> None:
    """The warning names the limit, the page count and the way in."""
    warning = script_app_warning([_page(_ANGULAR)])
    assert warning is not None
    assert "does not run JavaScript" in warning and "1 page(s)" in warning
    assert "--openapi" in warning
    assert "--har <file>" in warning and "network panel" in warning  # spec 021, RF-13


def test_the_warning_does_not_suggest_a_har_that_was_already_given() -> None:
    """With ``--har`` in use and the crawl still thin, the sentence keeps only the API advice."""
    warning = script_app_warning([_page(_ANGULAR)], har=True)
    assert warning is not None
    assert "--openapi" in warning and "--har" not in warning


def test_a_shell_that_still_yielded_a_surface_is_not_warned_about() -> None:
    """With --openapi (or any server-rendered part) the crawl is not thin: nothing to warn."""
    pages = [_page(_ANGULAR)] + [_page("<html></html>")] * 3
    assert script_app_warning(pages) is None


def test_an_entry_page_that_is_not_html_or_failed_is_not_warned_about() -> None:
    """A JSON entry point or an error page is not a shell."""
    assert script_app_warning([_page(_ANGULAR, content_type="application/json")]) is None
    assert script_app_warning([_page(_ANGULAR, status=500)]) is None
    assert script_app_warning([]) is None
