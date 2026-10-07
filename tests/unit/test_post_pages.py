"""
Passes that must not treat the answer to a crawler POST as a fetchable page — spec 018 RF-09.

A page the crawler reached by submitting a form (``Page.method == "POST"``) exists only as a
response: its URL is a form action that answers a ``GET`` with ``405``. The four sites that
re-request a page's URL, or derive a ``GET`` injection point from it, skip it; these tests give
each site one ``GET`` page and one ``POST`` page and assert only the first is used. The passes are
exercised directly (no HTTP): the stored-XSS pass has its ``_submit`` and ``Crawler`` replaced so
Phase B runs and its frontier can be read.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from tests.support import make_page
from webvigil.checks.disclosure.probe import DisclosureProbe
from webvigil.checks.envelope.scanner import EnvelopeScanner
from webvigil.checks.injection import stored as stored_module
from webvigil.checks.injection.points import enumerate_points
from webvigil.checks.injection.stored import StoredXssScanner
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.target import Target
from webvigil.crawler.forms import Form, FormField

_TARGET = Target.parse("https://example.com/")
_GET_URL = "https://example.com/catalog/list?page=1"
_POST_URL = "https://example.com/support/ticket?ref=7"


def _pages() -> tuple[Page, Page]:
    """
    Returns:
        tuple[Page, Page]: A page fetched with ``GET`` and the answer to a ``POST``,
            on different paths and each carrying a query parameter.
    """
    got = make_page(url=_GET_URL)
    answered = replace(make_page(url=_POST_URL), method="POST")
    return got, answered


def test_enumerate_points_ignores_a_post_answer() -> None:
    """A ``POST`` answer yields no ``GET`` injection point; a fetched page still does."""
    points, _ = enumerate_points(_pages(), (), max_points=50)
    assert [(point.method, point.base_url, point.param) for point in points] == [
        ("GET", "https://example.com/catalog/list", "page")
    ]


def test_the_envelope_sample_skips_a_post_answer() -> None:
    """The request-envelope pass never samples a URL only a ``POST`` reaches."""
    scanner = EnvelopeScanner(None, _TARGET, ScanConfig(), _pages(), ())  # type: ignore[arg-type]
    sample = scanner._sample_urls()
    assert _GET_URL in sample and _POST_URL not in sample


def test_the_probe_derives_directories_only_from_fetched_pages() -> None:
    """Directory prefixes come from ``GET`` pages: under ``/catalog/`` yes, ``/support/`` no."""
    probe = DisclosureProbe(None, _TARGET, (), _pages())  # type: ignore[arg-type]
    assert probe._discovered_dirs() == ["/catalog/", "/catalog/list/"]


async def test_the_stored_xss_recrawl_frontier_skips_a_post_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase B re-fetches only pages that were fetched with ``GET``."""
    captured: dict[str, Any] = {}

    class _CapturingCrawler:
        def __init__(self, *_a: object, **_k: object) -> None: ...

        async def recrawl(self, frontier: tuple[str, ...], **_k: object) -> list[Page]:
            captured["frontier"] = frontier
            return []

    async def _submitted(self: StoredXssScanner, *_a: object) -> object:
        return object()  # any non-None answer: the marker "went in"

    monkeypatch.setattr(stored_module, "Crawler", _CapturingCrawler)
    monkeypatch.setattr(StoredXssScanner, "_submit", _submitted)
    form = Form(
        method="POST",
        action="https://example.com/guestbook",
        enctype="application/x-www-form-urlencoded",
        fields=(FormField("body", "text", ""),),
        source_url=_GET_URL,
    )
    scanner = StoredXssScanner(None, _TARGET, ScanConfig(), _pages(), (form,))  # type: ignore[arg-type]
    await scanner.run()
    assert captured["frontier"] == (_GET_URL,)
