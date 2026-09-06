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
