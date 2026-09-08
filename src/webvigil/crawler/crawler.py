"""
Lightweight in-scope page discovery (RF-07).

BFS from the seed URL plus any sitemap seeds and ``--openapi`` GET operations
(spec 013), following ``<a href>`` links that stay in scope, bounded by
``max_pages``. GET only — no JavaScript. Since spec
007 the crawler also submits safe ``GET`` forms (search, filters) with their
default values (RF-05) and skips ``logout`` links (always) and — on an
authenticated crawl — links that look state-changing (RF-03). The ``<form>``
inventory it builds is exposed via :attr:`Crawler.forms`.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Sequence
from urllib.parse import urljoin, urlsplit

from selectolax.parser import HTMLParser

from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.core.target import Target, normalize_url
from webvigil.crawler import robots as robots_mod
from webvigil.crawler import sitemap as sitemap_mod
from webvigil.crawler.forms import Form, parse_forms, submission_url
from webvigil.crawler.safety import is_auth_form, is_destructive, is_logout
from webvigil.http.client import HttpClient

_SKIP_LINK_PREFIXES = ("mailto:", "tel:", "javascript:", "data:", "#")

_FormKey = tuple[str, str, tuple[str, ...]]


class Crawler:
    """
    Discovers in-scope pages for one scan.

    Also accumulates the deduplicated ``<form>`` inventory (:attr:`forms`) and
    counts how many links it declined to follow as state-changing
    (:attr:`skipped_destructive`).
    """

    def __init__(
        self,
        http: HttpClient,
        target: Target,
        config: ScanConfig,
        *,
        extra_seeds: Sequence[str] = (),
    ) -> None:
        """
        Args:
            http (HttpClient): The shared, scope-guarded HTTP client.
            target (Target): The normalized target and its scope rule.
            config (ScanConfig): The resolved scan configuration; supplies
                ``max_pages``, ``follow_robots``, ``submit_forms``, and whether
                the crawl is authenticated.
            extra_seeds (Sequence[str]): Absolute URLs to enqueue before the
                seed page's own links — the GET operations of an ``--openapi``
                import (spec 013). Scope / logout / destructive guards and
                ``max_pages`` still apply.
        """
        self._http = http
        self._target = target
        self._config = config
        self._user_agent = config.http.user_agent
        self._authenticated = bool(config.auth.cookies or config.auth.headers)
        self._submit_forms = config.scan.submit_forms
        self._extra_seeds = tuple(extra_seeds)
        self._forms: dict[_FormKey, Form] = {}
        self._skipped_destructive = 0

    @property
    def forms(self) -> tuple[Form, ...]:
        """
        Returns:
            tuple[Form, ...]: Every in-scope ``<form>`` seen during the crawl,
                de-duplicated by ``(method, action, field names)``.
        """
        return tuple(self._forms.values())

    @property
    def skipped_destructive(self) -> int:
        """
        Returns:
            int: How many links and GET forms the crawler declined to follow as
                state-changing (RF-03).
        """
        return self._skipped_destructive

    async def discover(self) -> list[Page]:
        """
        Crawl from the seed and return the discovered pages.

        Fetches the seed, enqueues its links, forms, and any sitemap seeds,
        then BFS-fetches the queue until it is empty or ``max_pages`` is
        reached. ``robots.txt`` gates the queue when ``follow_robots`` is on.

        Returns:
            list[Page]: The discovered pages, seed first, at most ``max_pages``.
        """
        max_pages = max(1, self._config.scan.max_pages)
        robots = await robots_mod.load(self._http, self._target.origin, self._user_agent)

        seed = normalize_url(self._target.entry_url)
        seen: set[str] = {seed}
        pages: list[Page] = [await self._fetch(seed)]

        queue: deque[str] = deque()
        for seed in self._extra_seeds:  # spec 013: API operations before the HTML surface
            self._maybe_enqueue(seed, seen, queue)
        self._enqueue_links(pages[0], seen, queue)
        self._collect_and_enqueue_forms(pages[0], seen, queue)
        await self._enqueue_sitemaps(robots, seen, queue)

        while queue and len(pages) < max_pages:
            url = queue.popleft()
            if self._config.scan.follow_robots and not robots.can_fetch(self._user_agent, url):
                continue
            page = await self._fetch(url)
            pages.append(page)
            self._enqueue_links(page, seen, queue)
            self._collect_and_enqueue_forms(page, seen, queue)

        return pages

    async def recrawl(
        self,
        frontier: Sequence[str],
        *,
        should_fetch: Callable[[], bool],
        max_fetches: int,
    ) -> list[Page]:
        """
        Re-fetch the frontier, then follow one hop of new links and safe GET forms.

        Used by the stored-XSS pass (spec 008, RF-05). Reuses the crawl's scope
        / logout / destructive / auth-form skips and ``submit_forms`` handling.
        Robots and sitemap are not re-consulted.

        Args:
            frontier (Sequence[str]): URLs from the first crawl to re-fetch;
                de-duplicated after normalization.
            should_fetch (Callable[[], bool]): Called immediately before each
                fetch — and, for a budget guard, consumes a slot. A ``False``
                return stops the re-crawl.
            max_fetches (int): Hard cap on pages fetched.

        Returns:
            list[Page]: The re-fetched frontier pages plus the one-hop pages,
                in fetch order.
        """
        seen: set[str] = {normalize_url(u) for u in frontier}
        pages: list[Page] = []
        queue: deque[str] = deque()

        for url in dict.fromkeys(normalize_url(u) for u in frontier):
            if len(pages) >= max_fetches or not should_fetch():
                return pages
            page = await self._fetch(url)
            pages.append(page)
            self._enqueue_links(page, seen, queue)
            self._collect_and_enqueue_forms(page, seen, queue)

        while queue and len(pages) < max_fetches and should_fetch():
            pages.append(await self._fetch(queue.popleft()))

        return pages

    async def _fetch(self, url: str) -> Page:
        """
        Fetch one URL, turning any transport or scope failure into a failed :class:`Page`.

        Args:
            url (str): The absolute URL to fetch.

        Returns:
            Page: The fetched page, or :meth:`Page.failed` on error.
        """
        try:
            response = await self._http.get(url)
        except (RequestFailed, OutOfScopeError) as exc:
            return Page.failed(url, str(exc))
        return Page.from_response(response)

    async def _enqueue_sitemaps(
        self, robots: robots_mod.Robots, seen: set[str], queue: deque[str]
    ) -> None:
        """
        Fetch the declared and conventional sitemaps and enqueue their in-scope URLs.

        Args:
            robots (robots_mod.Robots): Parsed robots, for its ``Sitemap:``
                declarations.
            seen (set[str]): Already-queued URLs, updated in place.
            queue (deque[str]): The BFS queue, appended to in place.
        """
        candidates = [*robots.sitemaps, f"{self._target.origin}/sitemap.xml"]
        for sitemap_url in candidates:
            for loc in await sitemap_mod.fetch(self._http, sitemap_url):
                self._maybe_enqueue(loc, seen, queue)

    def _enqueue_links(self, page: Page, seen: set[str], queue: deque[str]) -> None:
        """
        Enqueue every in-scope ``<a href>`` target on ``page``.

        Args:
            page (Page): The page whose links to walk; skipped when not OK HTML.
            seen (set[str]): Already-queued URLs, updated in place.
            queue (deque[str]): The BFS queue, appended to in place.
        """
        if not page.ok or not page.is_html:
            return
        for href in _extract_hrefs(page.text):
            self._maybe_enqueue(urljoin(page.url, href), seen, queue)

    def _maybe_enqueue(self, raw_url: str, seen: set[str], queue: deque[str]) -> None:
        """
        Normalize ``raw_url`` and enqueue it unless it is out of scope, seen, or unsafe.

        A logout URL, or — on an authenticated crawl — a destructive-looking
        URL, is marked seen but never queued (and the destructive counter is
        bumped).

        Args:
            raw_url (str): A candidate URL, possibly relative-resolved already.
            seen (set[str]): Already-queued URLs, updated in place.
            queue (deque[str]): The BFS queue, appended to in place.
        """
        if not urlsplit(raw_url).scheme.startswith("http"):
            return
        normalized = normalize_url(raw_url)
        if normalized in seen or not self._target.in_scope(normalized):
            return
        if is_logout(normalized):
            seen.add(normalized)  # do not revisit it via another link either
            return
        if self._authenticated and is_destructive(normalized):
            seen.add(normalized)
            self._skipped_destructive += 1
            return
        seen.add(normalized)
        queue.append(normalized)

    def _collect_and_enqueue_forms(self, page: Page, seen: set[str], queue: deque[str]) -> None:
        """
        Record every ``<form>`` on ``page`` and enqueue the safe ``GET`` ones' submissions.

        Auth forms and logout forms are never submitted; a destructive-looking
        action is skipped on an authenticated crawl (and counted).

        Args:
            page (Page): The page whose forms to walk; skipped when not OK HTML.
            seen (set[str]): Already-queued URLs, updated in place.
            queue (deque[str]): The BFS queue, appended to in place.
        """
        if not (page.ok and page.is_html):
            return
        for form in parse_forms(page, self._target):
            key = (form.method, form.action, tuple(f.name for f in form.fields))
            self._forms.setdefault(key, form)
            if not self._submit_forms or form.method != "GET":
                continue
            if is_auth_form(form) or is_logout(form.action):
                continue
            if self._authenticated and is_destructive(form.action):
                self._skipped_destructive += 1
                continue
            url = submission_url(form)
            if url is not None:
                self._maybe_enqueue(url, seen, queue)


def _extract_hrefs(html: str) -> list[str]:
    """
    Args:
        html (str): A page body.

    Returns:
        list[str]: The raw ``href`` values of every ``<a href>``, dropping
            ``mailto:`` / ``tel:`` / ``javascript:`` / ``data:`` / fragment
            links.
    """
    hrefs: list[str] = []
    for node in HTMLParser(html).css("a[href]"):
        href = (node.attributes.get("href") or "").strip()
        if href and not href.lower().startswith(_SKIP_LINK_PREFIXES):
            hrefs.append(href)
    return hrefs
