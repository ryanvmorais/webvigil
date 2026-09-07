"""Crawler discovery: max_pages, de-dup, robots, and sitemap handling — RF-07."""

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
    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    async with HttpClient(Target.parse(_SEED), config) as http:
        return await Crawler(http, Target.parse(_SEED), config).discover()


def _page(html: str) -> tuple[int, str, str]:
    return (200, html, "text/html; charset=utf-8")


async def test_seed_is_always_first_and_max_pages_caps_discovery(httpx_mock: object) -> None:
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
    router = _Router(
        {
            _SEED: _page(_html("/a", "/a#top", "/a", "HTTPS://Example.com/a")),
            "https://example.com/a": _page(_html()),
        }
    )
    pages = await _discover(ScanConfig(), router, httpx_mock)
    assert sorted(p.url for p in pages) == [_SEED, "https://example.com/a"]


async def test_robots_disallow_is_honored(httpx_mock: object) -> None:
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
    router = _Router(
        {
            "https://example.com/sitemap.xml": (200, "<<<not xml>>>", "application/xml"),
            _SEED: _page(_html()),
        }
    )
    pages = await _discover(ScanConfig(), router, httpx_mock)
    assert [p.url for p in pages] == [_SEED]


async def test_out_of_scope_links_are_not_followed(httpx_mock: object) -> None:
    router = _Router({_SEED: _page(_html("https://evil.test/x", "/local"))})
    router.routes["https://example.com/local"] = _page(_html())
    pages = await _discover(ScanConfig(), router, httpx_mock)
    assert all("evil.test" not in p.url for p in pages)
    assert "https://evil.test/x" not in router.seen


# --- spec 007: form-driven crawling and the safety heuristic (RF-03, RF-05, RF-06) ---

_AUTHED = ScanConfig.model_validate({"auth": {"cookies": ["session=abc"]}})


async def _crawl(config: ScanConfig, router: _Router, httpx_mock: object) -> Crawler:
    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    async with HttpClient(Target.parse(_SEED), config) as http:
        crawler = Crawler(http, Target.parse(_SEED), config)
        await crawler.discover()
        return crawler


async def test_a_get_search_form_is_submitted(httpx_mock: object) -> None:
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
    form = '<form method="post" action="/comment"><textarea name="b"></textarea></form>'
    router = _Router({_SEED: _page(form)})
    crawler = await _crawl(ScanConfig(), router, httpx_mock)
    assert [f.method for f in crawler.forms] == ["POST"]
    assert not any("/comment" in url for url in router.seen)


async def test_submit_forms_false_disables_form_submission(httpx_mock: object) -> None:
    router = _Router({_SEED: _page('<form method="get" action="/search"><input name="q"></form>')})
    config = ScanConfig.model_validate({"scan": {"submit_forms": False}})
    crawler = await _crawl(config, router, httpx_mock)
    assert not any("/search" in url for url in router.seen)
    assert len(crawler.forms) == 1  # still inventoried


async def test_logout_links_are_never_followed(httpx_mock: object) -> None:
    router = _Router(
        {_SEED: _page(_html("/logout", "/ok")), "https://example.com/ok": _page(_html())}
    )
    for config in (ScanConfig(), _AUTHED):
        router.seen.clear()
        await _crawl(config, router, httpx_mock)
        assert "https://example.com/logout" not in router.seen


async def test_destructive_links_are_skipped_only_when_authenticated(httpx_mock: object) -> None:
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


# --- spec 008: Crawler.recrawl — depth-1 re-crawl from a known frontier (RF-05) ------


async def _recrawl(
    config: ScanConfig,
    router: _Router,
    httpx_mock: object,
    frontier: list[str],
    *,
    max_fetches: int = 50,
    limit: int | None = None,
) -> list[Page]:
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
