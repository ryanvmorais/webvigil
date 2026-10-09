"""
The crawl keeps a bounded amount of what the scanned site declares, and still crawls ordinary sites.

``robots.txt``, the sitemaps and the pages all come from the scanned site, so how many sitemaps it
declares, how many links a page carries and how many forms it holds are the site's choice. The real
:class:`Crawler` runs against a ``_Router`` (an ``httpx_mock`` callback that serves a URL to
``(status, body, content_type)`` map, defaults to 404 and records every URL it is asked for), so the
request counts are real. :func:`parse_forms` and :func:`sitemap.parse` get real strings. Nothing
else is mocked.
"""

from __future__ import annotations

from collections import deque

import httpx
import pytest

from tests.support import make_page
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.target import Target
from webvigil.crawler import sitemap
from webvigil.crawler.crawler import Crawler
from webvigil.crawler.forms import MAX_FIELDS_PER_FORM, MAX_FORMS_PER_PAGE, parse_forms
from webvigil.http.client import HttpClient

pytestmark = pytest.mark.httpx_mock(assert_all_responses_were_requested=False)

_SEED = "https://example.com/"
_TARGET = Target.parse(_SEED)


class _Router:
    """Routes mocked requests by URL, defaulting to 404, and records every URL asked for."""

    def __init__(self, routes: dict[str, tuple[int, str, str]]) -> None:
        self.routes = routes
        self.seen: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.seen.append(url)
        status, body, content_type = self.routes.get(url, (404, "", "text/plain"))
        return httpx.Response(status_code=status, text=body, headers={"content-type": content_type})


class _CountingCrawler(Crawler):
    """A crawler that counts the links it is asked to consider."""

    considered = 0

    def _maybe_enqueue(self, raw_url: str, seen: set[str], queue: deque[str]) -> None:
        type(self).considered += 1
        super()._maybe_enqueue(raw_url, seen, queue)


async def _crawl(
    router: _Router, httpx_mock: object, *, max_pages: int = 50
) -> tuple[Crawler, list[Page]]:
    """
    Args:
        router (_Router): The response router.
        httpx_mock: The ``pytest-httpx`` fixture.
        max_pages (int): The page cap. Defaults to 50.

    Returns:
        tuple[Crawler, list[Page]]: The crawler after ``discover()`` and its pages.
    """
    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    config = ScanConfig()
    config.scan.max_pages = max_pages
    async with HttpClient(_TARGET, config) as http:
        crawler = Crawler(http, _TARGET, config)
        pages = await crawler.discover()
    return crawler, list(pages)


def _sitemap_xml(count: int) -> str:
    """
    Args:
        count (int): How many ``<loc>`` entries.

    Returns:
        str: A sitemap with ``count`` distinct in-scope URLs.
    """
    locs = "".join(f"<url><loc>{_SEED}p/{i}</loc></url>" for i in range(count))
    return f'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{locs}</urlset>'


# ---------------------------------------------------------------------------
# robots.txt and sitemaps: how many are read
# ---------------------------------------------------------------------------


async def test_a_robots_file_declaring_many_sitemaps_gets_a_bounded_number_of_requests(
    httpx_mock: object,
) -> None:
    """Only the first ``MAX_SITEMAPS`` declared sitemaps (and the conventional one) are fetched."""
    declared = "".join(f"Sitemap: {_SEED}s/{i}.xml\n" for i in range(100))
    router = _Router(
        {
            _SEED: (200, "<html><body>hi</body></html>", "text/html"),
            f"{_SEED}robots.txt": (200, declared, "text/plain"),
        }
    )
    crawler, _ = await _crawl(router, httpx_mock)
    fetched = [u for u in router.seen if "/s/" in u or u.endswith("/sitemap.xml")]
    assert len(fetched) <= sitemap.MAX_SITEMAPS + 1
    assert crawler.limit_warning is not None
    assert "sitemaps" in crawler.limit_warning


def test_a_sitemap_gives_at_most_the_url_limit() -> None:
    """A sitemap with more entries than the limit returns the first ``MAX_URLS`` of them."""
    xml = _sitemap_xml(sitemap.MAX_URLS + 500)
    assert len(sitemap.parse(xml)) == sitemap.MAX_URLS
    assert sitemap.parse(xml, limit=5) == [f"{_SEED}p/{i}" for i in range(5)]


async def test_all_the_sitemaps_together_give_at_most_the_url_limit(httpx_mock: object) -> None:
    """The URL limit is shared by the sitemaps of a scan, not applied to each."""
    routes = {
        _SEED: (200, "<html><body>hi</body></html>", "text/html"),
        f"{_SEED}robots.txt": (
            200,
            f"Sitemap: {_SEED}a.xml\nSitemap: {_SEED}b.xml\n",
            "text/plain",
        ),
        f"{_SEED}a.xml": (200, _sitemap_xml(sitemap.MAX_URLS), "application/xml"),
        f"{_SEED}b.xml": (200, _sitemap_xml(sitemap.MAX_URLS), "application/xml"),
    }
    crawler, _ = await _crawl(_Router(routes), httpx_mock)
    assert crawler.limit_warning is not None
    assert "sitemap URLs" in crawler.limit_warning


# ---------------------------------------------------------------------------
# Pages: how many links and forms are kept
# ---------------------------------------------------------------------------


def test_the_set_of_urls_seen_stays_bounded() -> None:
    """Thirty thousand distinct in-scope links enqueue at most ``max(10_000, 20 * max_pages)``."""
    config = ScanConfig()
    crawler = Crawler(HttpClient(_TARGET, config), _TARGET, config)
    seen: set[str] = set()
    queue: deque[str] = deque()
    for i in range(30_000):
        crawler._maybe_enqueue(f"{_SEED}p/{i}", seen, queue)
    assert len(queue) == 10_000
    assert crawler.limit_warning is not None
    assert "links" in crawler.limit_warning


def test_one_page_gives_at_most_the_per_page_link_limit() -> None:
    """A page that repeats a link fifty thousand times is read up to the per-page limit."""
    config = ScanConfig()
    crawler = _CountingCrawler(HttpClient(_TARGET, config), _TARGET, config)
    _CountingCrawler.considered = 0
    html = "<html><body>" + '<a href="/same">x</a>' * 50_000 + "</body></html>"
    crawler._enqueue_links(make_page(text=html), set(), deque())
    assert _CountingCrawler.considered == 20_000


async def test_the_pages_fetched_are_the_same_with_a_huge_link_list(httpx_mock: object) -> None:
    """A page with more links than any limit still gives the first ``max_pages`` pages."""
    links = "".join(f'<a href="/p/{i}">x</a>' for i in range(25_000))
    routes: dict[str, tuple[int, str, str]] = {
        _SEED: (200, f"<html><body>{links}</body></html>", "text/html")
    }
    router = _Router(routes)
    _, pages = await _crawl(router, httpx_mock, max_pages=5)
    assert [p.url for p in pages] == [_SEED, *(f"{_SEED}p/{i}" for i in range(4))]


async def test_the_form_inventory_stays_bounded(httpx_mock: object) -> None:
    """Distinct forms past the inventory limit are left out, with a warning."""
    # One page holds at most MAX_FORMS_PER_PAGE forms, so spread them over linked pages.
    routes: dict[str, tuple[int, str, str]] = {}
    links = "".join(f'<a href="/page{n}">x</a>' for n in range(5))
    routes[_SEED] = (200, f"<html><body>{links}</body></html>", "text/html")
    for n in range(5):
        forms = "".join(
            f'<form action="/f{n * MAX_FORMS_PER_PAGE + i}"><input name="q"></form>'
            for i in range(MAX_FORMS_PER_PAGE)
        )
        routes[f"{_SEED}page{n}"] = (200, f"<html><body>{forms}</body></html>", "text/html")
    crawler, _ = await _crawl(_Router(routes), httpx_mock)
    assert len(crawler.forms) == 2_000
    assert crawler.limit_warning is not None
    assert "forms" in crawler.limit_warning


def test_one_page_gives_at_most_the_per_page_form_limit() -> None:
    """A page holding more forms than the limit is read up to the limit."""
    forms = "".join(f'<form action="/f{i}"><input name="q"></form>' for i in range(900))
    page = make_page(text=f"<html><body>{forms}</body></html>")
    assert len(parse_forms(page, _TARGET)) == MAX_FORMS_PER_PAGE


def test_one_form_gives_at_most_the_field_limit() -> None:
    """A form holding more controls than the limit is read up to the limit."""
    inputs = "".join(f'<input name="n{i}">' for i in range(2_500))
    page = make_page(text=f'<html><body><form action="/f">{inputs}</form></body></html>')
    (form,) = parse_forms(page, _TARGET)
    assert len(form.fields) == MAX_FIELDS_PER_FORM


# ---------------------------------------------------------------------------
# Behaviour: an ordinary site is crawled as before
# ---------------------------------------------------------------------------


async def test_an_ordinary_site_reaches_no_limit(httpx_mock: object) -> None:
    """A few sitemaps, links and forms: nothing is left out and no warning is raised."""
    routes = {
        _SEED: (
            200,
            '<html><body><a href="/a">a</a><form action="/s"><input name="q"></form></body></html>',
            "text/html",
        ),
        f"{_SEED}robots.txt": (200, f"Sitemap: {_SEED}sitemap-1.xml\n", "text/plain"),
        f"{_SEED}sitemap-1.xml": (200, _sitemap_xml(3), "application/xml"),
        f"{_SEED}a": (200, "<html><body>a</body></html>", "text/html"),
    }
    crawler, pages = await _crawl(_Router(routes), httpx_mock)
    assert crawler.limit_warning is None
    urls = [p.url for p in pages]
    assert f"{_SEED}a" in urls
    assert any(u.startswith(f"{_SEED}p/") for u in urls)
    assert len(crawler.forms) == 1
