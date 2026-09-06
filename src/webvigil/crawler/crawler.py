"""Lightweight in-scope page discovery (RF-07).

BFS from the seed URL plus any sitemap seeds, following ``<a href>`` links that stay in
scope, bounded by ``max_pages``. GET only — no forms, no JavaScript.
"""

from __future__ import annotations

from collections import deque
from urllib.parse import urljoin, urlsplit

from selectolax.parser import HTMLParser

from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.core.target import Target, normalize_url
from webvigil.crawler import robots as robots_mod
from webvigil.crawler import sitemap as sitemap_mod
from webvigil.http.client import HttpClient

_SKIP_LINK_PREFIXES = ("mailto:", "tel:", "javascript:", "data:", "#")


class Crawler:
    """Discovers in-scope pages for one scan."""

    def __init__(self, http: HttpClient, target: Target, config: ScanConfig) -> None:
        self._http = http
        self._target = target
        self._config = config
        self._user_agent = config.http.user_agent

    async def discover(self) -> list[Page]:
        """Return the discovered pages, seed first, at most ``max_pages`` of them."""
        max_pages = max(1, self._config.scan.max_pages)
        robots = await robots_mod.load(self._http, self._target.origin, self._user_agent)

        seed = normalize_url(self._target.entry_url)
        seen: set[str] = {seed}
        pages: list[Page] = [await self._fetch(seed)]

        queue: deque[str] = deque()
        self._enqueue_links(pages[0], seen, queue)
        await self._enqueue_sitemaps(robots, seen, queue)

        while queue and len(pages) < max_pages:
            url = queue.popleft()
            if self._config.scan.follow_robots and not robots.can_fetch(self._user_agent, url):
                continue
            page = await self._fetch(url)
            pages.append(page)
            self._enqueue_links(page, seen, queue)

        return pages

    async def _fetch(self, url: str) -> Page:
        try:
            response = await self._http.get(url)
        except (RequestFailed, OutOfScopeError) as exc:
            return Page.failed(url, str(exc))
        return Page.from_response(response)

    async def _enqueue_sitemaps(
        self, robots: robots_mod.Robots, seen: set[str], queue: deque[str]
    ) -> None:
        candidates = [*robots.sitemaps, f"{self._target.origin}/sitemap.xml"]
        for sitemap_url in candidates:
            for loc in await sitemap_mod.fetch(self._http, sitemap_url):
                self._maybe_enqueue(loc, seen, queue)

    def _enqueue_links(self, page: Page, seen: set[str], queue: deque[str]) -> None:
        if not page.ok or not page.is_html:
            return
        for href in _extract_hrefs(page.text):
            self._maybe_enqueue(urljoin(page.url, href), seen, queue)

    def _maybe_enqueue(self, raw_url: str, seen: set[str], queue: deque[str]) -> None:
        if not urlsplit(raw_url).scheme.startswith("http"):
            return
        normalized = normalize_url(raw_url)
        if normalized in seen or not self._target.in_scope(normalized):
            return
        seen.add(normalized)
        queue.append(normalized)


def _extract_hrefs(html: str) -> list[str]:
    hrefs: list[str] = []
    for node in HTMLParser(html).css("a[href]"):
        href = (node.attributes.get("href") or "").strip()
        if href and not href.lower().startswith(_SKIP_LINK_PREFIXES):
            hrefs.append(href)
    return hrefs
