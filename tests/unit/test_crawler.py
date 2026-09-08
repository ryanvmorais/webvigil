"""
Crawler discovery: max_pages, de-dup, robots, and sitemap handling — RF-07.

The real :class:`Crawler` runs against a ``_Router`` — an ``httpx_mock`` callback
that serves a URL→``(status, body, content_type)`` map, defaults to 404, and
records every URL it is asked for, so the "not followed" assertions are real.
``_discover`` / ``_crawl`` / ``_recrawl`` are the three entry points, each
wrapping the crawler in a live :class:`HttpClient`.
"""

from __future__ import annotations

import httpx
import pytest

from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.target import Target
from webvigil.crawler.crawler import Crawler
from webvigil.http.client import HttpClient

pytestmark = pytest.mark.httpx_mock(assert_all_responses_were_requested=False)

_SEED = "https://example.com/"


def _html(*links: str) -> str:
    """
    Args:
        *links (str): The ``href`` values to turn into ``<a>`` tags.

    Returns:
        str: A minimal HTML page linking to each of ``links``.
    """
    body = "".join(f'<a href="{href}">x</a>' for href in links)
    return f"<html><body>{body}</body></html>"


class _Router:
    """Routes mocked requests by URL, defaulting to 404."""

    def __init__(self, routes: dict[str, tuple[int, str, str]]) -> None:
        self.routes = routes
        self.seen: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.seen.append(url)
        status, body, content_type = self.routes.get(url, (404, "", "text/plain"))
        return httpx.Response(status_code=status, text=body, headers={"content-type": content_type})


async def _discover(config: ScanConfig, router: _Router, httpx_mock: object) -> list[Page]:
    """
    Args:
        config (ScanConfig): The scan config.
        router (_Router): The response router.
        httpx_mock: The ``pytest-httpx`` fixture.

    Returns:
        list[Page]: The pages the crawler discovered.
    """
    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    async with HttpClient(Target.parse(_SEED), config) as http:
        return await Crawler(http, Target.parse(_SEED), config).discover()


def _page(html: str) -> tuple[int, str, str]:
    """
    Args:
        html (str): The page body.

    Returns:
        tuple[int, str, str]: A ``(200, html, "text/html")`` route entry.
    """
    return (200, html, "text/html; charset=utf-8")


async def test_seed_is_always_first_and_max_pages_caps_discovery(httpx_mock: object) -> None:
    """The seed URL is page one and ``max_pages`` caps the total discovered."""
    router = _Router(
        {
            _SEED: _page(_html("/a", "/b", "/c")),
            "https://example.com/a": _page(_html()),
            "https://example.com/b": _page(_html()),
            "https://example.com/c": _page(_html()),
        }
    )
    pages = await _discover(
        ScanConfig.model_validate({"scan": {"max_pages": 2}}), router, httpx_mock
    )
    assert len(pages) == 2
    assert pages[0].url == _SEED


async def test_links_are_normalized_and_de_duplicated(httpx_mock: object) -> None:
    """Fragment, case, and repeat variants of one link collapse to a single fetch."""
    router = _Router(
        {
            _SEED: _page(_html("/a", "/a#top", "/a", "HTTPS://Example.com/a")),
            "https://example.com/a": _page(_html()),
        }
    )
    pages = await _discover(ScanConfig(), router, httpx_mock)
    assert sorted(p.url for p in pages) == [_SEED, "https://example.com/a"]


async def test_robots_disallow_is_honored(httpx_mock: object) -> None:
    """A ``Disallow`` in robots.txt keeps the matching path out of the crawl by default."""
    router = _Router(
        {
            "https://example.com/robots.txt": (
                200,
                "User-agent: *\nDisallow: /private\n",
                "text/plain",
            ),
            _SEED: _page(_html("/private/x", "/ok")),
            "https://example.com/ok": _page(_html()),
            "https://example.com/private/x": _page(_html()),
        }
    )
    pages = await _discover(ScanConfig(), router, httpx_mock)
    urls = {p.url for p in pages}
    assert "https://example.com/ok" in urls
    assert "https://example.com/private/x" not in urls


async def test_robots_is_ignored_when_follow_robots_is_false(httpx_mock: object) -> None:
    """With ``follow_robots=False`` a disallowed path is crawled anyway."""
    router = _Router(
        {
            "https://example.com/robots.txt": (
                200,
                "User-agent: *\nDisallow: /private\n",
                "text/plain",
            ),
            _SEED: _page(_html("/private/x")),
            "https://example.com/private/x": _page(_html()),
        }
    )
    config = ScanConfig.model_validate({"scan": {"follow_robots": False}})
    pages = await _discover(config, router, httpx_mock)
    assert "https://example.com/private/x" in {p.url for p in pages}


async def test_malformed_sitemap_is_ignored(httpx_mock: object) -> None:
    """A sitemap that is not valid XML is skipped, not fatal."""
    router = _Router(
        {
            "https://example.com/sitemap.xml": (200, "<<<not xml>>>", "application/xml"),
            _SEED: _page(_html()),
        }
    )
    pages = await _discover(ScanConfig(), router, httpx_mock)
    assert [p.url for p in pages] == [_SEED]


async def test_out_of_scope_links_are_not_followed(httpx_mock: object) -> None:
    """An off-host link is never requested; an in-scope sibling still is."""
    router = _Router({_SEED: _page(_html("https://evil.test/x", "/local"))})
    router.routes["https://example.com/local"] = _page(_html())
    pages = await _discover(ScanConfig(), router, httpx_mock)
    assert all("evil.test" not in p.url for p in pages)
    assert "https://evil.test/x" not in router.seen


async def test_extra_seeds_are_fetched_scope_guarded_and_de_duplicated(httpx_mock: object) -> None:
    """``extra_seeds`` (spec 013) are crawled, kept in scope, and not re-fetched from a link."""
    router = _Router(
        {
            _SEED: _page(_html("/api/search?q=wv")),
            "https://example.com/api/search?q=wv": _page(_html()),
            "https://example.com/api/orphan": _page(_html()),
        }
    )
    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    seeds = [
        "https://example.com/api/search?q=wv",  # also linked from the seed page
        "https://example.com/api/orphan",  # linked from nowhere
        "https://evil.test/api/leak",  # out of scope
    ]
    async with HttpClient(Target.parse(_SEED), ScanConfig()) as http:
        pages = await Crawler(http, Target.parse(_SEED), ScanConfig(), extra_seeds=seeds).discover()
    urls = [p.url for p in pages]
    assert "https://example.com/api/orphan" in urls
    assert urls.count("https://example.com/api/search?q=wv") == 1
    assert not any("evil.test" in u for u in router.seen)


async def test_an_extra_seed_blocked_by_robots_is_skipped(httpx_mock: object) -> None:
    """A seed disallowed by ``robots.txt`` is not fetched when ``follow_robots`` is on."""
    router = _Router(
        {
            _SEED: _page(_html()),
            "https://example.com/robots.txt": (200, "User-agent: *\nDisallow: /api/", "text/plain"),
            "https://example.com/api/hidden": _page(_html()),
        }
    )
    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    async with HttpClient(Target.parse(_SEED), ScanConfig()) as http:
        pages = await Crawler(
            http,
            Target.parse(_SEED),
            ScanConfig(),
            extra_seeds=["https://example.com/api/hidden"],
        ).discover()
    assert all("api/hidden" not in p.url for p in pages)


# ---------------------------------------------------------------------------
# Form-driven crawling and the safety heuristic (spec 007 RF-03, RF-05, RF-06)
# ---------------------------------------------------------------------------

_AUTHED = ScanConfig.model_validate({"auth": {"cookies": ["session=abc"]}})


async def _crawl(config: ScanConfig, router: _Router, httpx_mock: object) -> Crawler:
    """
    Args:
        config (ScanConfig): The scan config.
        router (_Router): The response router.
        httpx_mock: The ``pytest-httpx`` fixture.

    Returns:
        Crawler: The crawler after ``discover()`` has run, for its ``forms`` and counters.
    """
    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    async with HttpClient(Target.parse(_SEED), config) as http:
        crawler = Crawler(http, Target.parse(_SEED), config)
        await crawler.discover()
        return crawler


async def test_a_get_search_form_is_submitted(httpx_mock: object) -> None:
    """A safe GET search form is submitted with empty values and its URL is crawled."""
    router = _Router(
        {
            _SEED: _page('<form method="get" action="/search"><input name="q"></form>'),
            "https://example.com/search?q=": _page(_html()),
        }
    )
    crawler = await _crawl(ScanConfig(), router, httpx_mock)
    assert "https://example.com/search?q=" in router.seen
    assert any(f.action == "https://example.com/search" for f in crawler.forms)


async def test_a_post_form_is_recorded_but_never_submitted(httpx_mock: object) -> None:
    """A POST form is inventoried but never sent by the crawler."""
    form = '<form method="post" action="/comment"><textarea name="b"></textarea></form>'
    router = _Router({_SEED: _page(form)})
    crawler = await _crawl(ScanConfig(), router, httpx_mock)
    assert [f.method for f in crawler.forms] == ["POST"]
    assert not any("/comment" in url for url in router.seen)


async def test_submit_forms_false_disables_form_submission(httpx_mock: object) -> None:
    """``submit_forms=False`` stops a safe GET form being submitted; it is still inventoried."""
    router = _Router({_SEED: _page('<form method="get" action="/search"><input name="q"></form>')})
    config = ScanConfig.model_validate({"scan": {"submit_forms": False}})
    crawler = await _crawl(config, router, httpx_mock)
    assert not any("/search" in url for url in router.seen)
    assert len(crawler.forms) == 1  # still inventoried


async def test_logout_links_are_never_followed(httpx_mock: object) -> None:
    """A logout link is skipped whether or not the scan is authenticated."""
    router = _Router(
        {_SEED: _page(_html("/logout", "/ok")), "https://example.com/ok": _page(_html())}
    )
    for config in (ScanConfig(), _AUTHED):
        router.seen.clear()
        await _crawl(config, router, httpx_mock)
        assert "https://example.com/logout" not in router.seen


async def test_destructive_links_are_skipped_only_when_authenticated(httpx_mock: object) -> None:
    """A destructive link is skipped (and counted) only under an authenticated scan."""
    links = _html("/items/5/delete", "/ok")
    router = _Router(
        {
            _SEED: _page(links),
            "https://example.com/items/5/delete": _page(_html()),
            "https://example.com/ok": _page(_html()),
        }
    )
    router.seen.clear()
    crawler = await _crawl(_AUTHED, router, httpx_mock)
    assert "https://example.com/items/5/delete" not in router.seen
    assert crawler.skipped_destructive == 1

    router.seen.clear()
    crawler = await _crawl(ScanConfig(), router, httpx_mock)
    assert "https://example.com/items/5/delete" in router.seen
    assert crawler.skipped_destructive == 0


async def test_submitted_form_urls_count_against_max_pages(httpx_mock: object) -> None:
    """A submitted form URL is a page like any other and counts toward ``max_pages``."""
    router = _Router(
        {
            _SEED: _page(
                _html("/a") + '<form method="get" action="/search"><input name="q"></form>'
            ),
            "https://example.com/a": _page(_html()),
            "https://example.com/search?q=": _page(_html()),
        }
    )
    pages = await _discover(
        ScanConfig.model_validate({"scan": {"max_pages": 2}}), router, httpx_mock
    )
    assert len(pages) == 2


# ---------------------------------------------------------------------------
# Crawler.recrawl — depth-1 re-crawl from a known frontier (spec 008 RF-05)
# ---------------------------------------------------------------------------


async def _recrawl(
    config: ScanConfig,
    router: _Router,
    httpx_mock: object,
    frontier: list[str],
    *,
    max_fetches: int = 50,
    limit: int | None = None,
) -> list[Page]:
    """
    Args:
        config (ScanConfig): The scan config.
        router (_Router): The response router.
        httpx_mock: The ``pytest-httpx`` fixture.
        frontier (list[str]): The URLs to re-fetch and follow one hop past.
        max_fetches (int): The hard fetch cap passed to ``recrawl``.
        limit (int | None): If set, ``should_fetch`` returns ``False`` after this
            many grants.

    Returns:
        list[Page]: The pages the re-crawl fetched.
    """
    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    budget = [0]

    def should_fetch() -> bool:
        if limit is not None and budget[0] >= limit:
            return False
        budget[0] += 1
        return True

    async with HttpClient(Target.parse(_SEED), config) as http:
        crawler = Crawler(http, Target.parse(_SEED), config)
        return await crawler.recrawl(frontier, should_fetch=should_fetch, max_fetches=max_fetches)


async def test_recrawl_refetches_the_frontier_and_follows_one_new_hop(httpx_mock: object) -> None:
    """The re-crawl re-fetches the frontier and follows exactly one new hop, not two."""
    router = _Router(
        {
            _SEED: _page(_html("/guestbook")),
            "https://example.com/guestbook": _page(_html("/guestbook/e/1")),
            "https://example.com/guestbook/e/1": _page(_html("/guestbook/e/1/raw")),
            "https://example.com/guestbook/e/1/raw": _page(_html()),
        }
    )
    pages = await _recrawl(
        ScanConfig(), router, httpx_mock, [_SEED, "https://example.com/guestbook"]
    )
    fetched = {p.url for p in pages}
    assert _SEED in fetched and "https://example.com/guestbook" in fetched
    assert "https://example.com/guestbook/e/1" in fetched  # one hop past the frontier
    assert "https://example.com/guestbook/e/1/raw" not in fetched  # not a second hop


async def test_recrawl_stops_when_should_fetch_returns_false(httpx_mock: object) -> None:
    """The re-crawl stops asking for pages once ``should_fetch`` says no."""
    router = _Router(
        {
            _SEED: _page(_html("/a")),
            "https://example.com/a": _page(_html()),
            "https://example.com/b": _page(_html()),
        }
    )
    pages = await _recrawl(
        ScanConfig(),
        router,
        httpx_mock,
        [_SEED, "https://example.com/b"],
        limit=1,
    )
    assert len(pages) == 1


async def test_recrawl_caps_at_max_fetches(httpx_mock: object) -> None:
    """``max_fetches`` is a hard ceiling on the re-crawl regardless of the frontier size."""
    router = _Router({f"https://example.com/p{i}": _page(_html()) for i in range(5)})
    pages = await _recrawl(
        ScanConfig(),
        router,
        httpx_mock,
        [f"https://example.com/p{i}" for i in range(5)],
        max_fetches=3,
    )
    assert len(pages) == 3


async def test_recrawl_skips_a_new_logout_or_destructive_link(httpx_mock: object) -> None:
    """The same logout/destructive safety guard applies to links found during the re-crawl."""
    router = _Router(
        {
            _SEED: _page(_html("/logout", "/items/9/delete", "/ok")),
            "https://example.com/ok": _page(_html()),
            "https://example.com/logout": _page(_html()),
            "https://example.com/items/9/delete": _page(_html()),
        }
    )
    pages = await _recrawl(_AUTHED, router, httpx_mock, [_SEED])
    fetched = {p.url for p in pages}
    assert "https://example.com/ok" in fetched
    assert "https://example.com/logout" not in fetched
    assert "https://example.com/items/9/delete" not in fetched
