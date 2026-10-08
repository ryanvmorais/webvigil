"""
Does the entry page look like a JavaScript application the crawler cannot see into?

The crawler fetches HTML and follows ``<a>`` and ``<form>``; it does not run scripts. A single-page
application answers with a shell (an empty ``<app-root>`` or ``<div id="root">`` and a bundle) and
draws its routes, forms and API calls in the browser, so the crawl ends at one page and the
injection passes have nothing to test. A scan that finds nothing there says nothing about the
application, but reads like "no findings". :func:`script_app_warning` is the sentence that says it.
"""

from __future__ import annotations

from collections.abc import Sequence

from selectolax.parser import HTMLParser

from webvigil.core.context import Page

# A page with fewer visible characters than this, once scripts, styles and <noscript> are set aside,
# has no content of its own. A real page, even a sparse one, is above it.
_MIN_VISIBLE_CHARS = 120

# At most this many pages: the shell plus a page or two that were reachable without scripts. More
# than that and the crawl found a surface (a server-rendered part, or an --openapi seed).
_THIN_CRAWL = 2

# <script> blocks that carry data, not code.
_DATA_SCRIPT_TYPES = ("application/ld+json", "application/json", "importmap", "speculationrules")


def looks_like_script_app(html: str) -> bool:
    """
    Args:
        html (str): The body of the entry page.

    Returns:
        bool: ``True`` when the page runs at least one script and shows almost no text without
            them: the shape of a client-rendered application shell.
    """
    tree = HTMLParser(html)
    body = tree.body
    if body is None:
        return False
    runs_scripts = any(
        node.attributes.get("src")
        or (
            (node.attributes.get("type") or "").lower() not in _DATA_SCRIPT_TYPES
            and (node.text() or "").strip()
        )
        for node in tree.css("script")
    )
    if not runs_scripts:
        return False
    for node in body.css("script, style, noscript, template"):
        node.decompose()
    visible = " ".join((body.text(separator=" ") or "").split())
    return len(visible) < _MIN_VISIBLE_CHARS


def script_app_warning(pages: Sequence[Page]) -> str | None:
    """
    The scan warning for a crawl that stopped at a JavaScript application's shell.

    Args:
        pages (Sequence[Page]): The pages the crawl discovered, entry page first.

    Returns:
        str | None: The warning text, or ``None`` when the crawl found a surface or the entry page
            has content of its own.
    """
    if not pages or len(pages) > _THIN_CRAWL:
        return None
    entry = pages[0]
    if entry.error or entry.status_code >= 400:
        return None
    if "html" not in entry.headers.get("content-type", "").lower():
        return None
    if not looks_like_script_app(entry.text):
        return None
    return (
        "the entry page looks like a JavaScript application (almost no content of its own; scripts "
        f"build it): WebVigil does not run JavaScript, so it found {len(pages)} page(s) and the "
        "results cover little of the application. Give it the API with --openapi <file>"
    )


__all__ = ["looks_like_script_app", "script_app_warning"]
