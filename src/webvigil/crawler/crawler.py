"""
Lightweight in-scope page discovery (RF-07).

BFS from the seed URL plus any sitemap seeds and ``--openapi`` GET operations
(spec 013), following ``<a href>`` links that stay in scope, bounded by
``max_pages``. GET only — no JavaScript. Since spec
007 the crawler also submits safe ``GET`` forms (search, filters) with their
default values (RF-05) and skips ``logout`` links (always) and — on an
authenticated crawl — links that look state-changing (RF-03). The ``<form>``
inventory it builds is exposed via :attr:`Crawler.forms`.

Since spec 018 the crawler can also **write**: with ``[scan] submit_post_forms`` on, in
Active Mode only, a ``POST`` phase runs after the ``GET`` queue drains. It submits each
distinct candidate form (urlencoded, or multipart with no file input) and each ``POST``
operation of an ``--openapi`` import once, with the form's own default values and a benign
``wvcrawl<token>`` marker for a field that has none — never a payload — and treats each
answer as a page: it is kept, and the links and forms on it feed the same BFS again. The
records it creates stay on the target.
"""

from __future__ import annotations

import secrets
from collections import deque
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from urllib.parse import urlencode, urljoin, urlsplit

from selectolax.lexbor import LexborHTMLParser as HTMLParser

from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.core.findings import ScanMode
from webvigil.core.target import Target, normalize_url
from webvigil.crawler import robots as robots_mod
from webvigil.crawler import sitemap as sitemap_mod
from webvigil.crawler.forms import Form, form_body, parse_forms, submission_url
from webvigil.crawler.openapi import ApiOperation
from webvigil.crawler.safety import (
    is_auth_form,
    is_candidate,
    is_destructive,
    is_destructive_form,
    is_logout,
    looks_unsafe_operation,
)
from webvigil.http.client import HttpClient

_SKIP_LINK_PREFIXES = ("mailto:", "tel:", "javascript:", "data:", "#")

_FormKey = tuple[str, str, tuple[str, ...]]
_OpKey = tuple[str, str, str]

_URLENCODED = "application/x-www-form-urlencoded"
_MULTIPART = "multipart/form-data"


@dataclass(slots=True)
class PostSummary:
    """
    What the ``POST`` phase did, for the one scan warning the orchestrator writes.

    Attributes:
        forms (int): Forms submitted.
        operations (int): ``--openapi`` operations submitted.
        skipped (int): ``POST`` forms and operations left out for a safety, shape
            or ``robots.txt`` reason, counted once each.
        over_cap (int): Candidates left unsubmitted by ``max_post_submissions`` or
            ``max_pages``.
    """

    forms: int = 0
    operations: int = 0
    skipped: int = 0
    over_cap: int = 0

    def warning(self) -> str | None:
        """
        Returns:
            str | None: The one-line tally, or ``None`` when the phase had nothing
                to submit and skipped nothing.
        """
        if not (self.forms or self.operations or self.skipped or self.over_cap):
            return None
        return (
            f"POST crawl: {self.forms + self.operations} submitted — "
            f"{self.forms} {'form' if self.forms == 1 else 'forms'}, "
            f"{self.operations} API {'operation' if self.operations == 1 else 'operations'}, "
            f"{self.skipped} skipped, {self.over_cap} not submitted (cap)"
        )


class Crawler:
    """
    Discovers in-scope pages for one scan.

    Also accumulates the deduplicated ``<form>`` inventory (:attr:`forms`) and
    counts how many links it declined to follow as state-changing
    (:attr:`skipped_destructive`) or because ``robots.txt`` disallows them
    (:attr:`skipped_by_robots`).
    """

    def __init__(
        self,
        http: HttpClient,
        target: Target,
        config: ScanConfig,
        *,
        extra_seeds: Sequence[str] = (),
        post_operations: Sequence[ApiOperation] = (),
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
            post_operations (Sequence[ApiOperation]): The ``POST`` operations of an
                ``--openapi`` import (spec 018); submitted by the ``POST`` phase when it
                is on, after the forms.
        """
        self._http = http
        self._target = target
        self._config = config
        self._user_agent = config.http.user_agent
        self._authenticated = config.auth.configured
        self._submit_forms = config.scan.submit_forms
        self._extra_seeds = tuple(extra_seeds)
        self._forms: dict[_FormKey, Form] = {}
        self._skipped_destructive = 0
        self._skipped_by_robots = 0
        # spec 018: the POST phase runs only when asked for AND the scan is Active.
        self._post_enabled = config.scan.submit_post_forms and config.scan.mode is ScanMode.ACTIVE
        self._post_cap = config.scan.max_post_submissions
        self._post_ops = tuple(post_operations)
        self._marker = f"wvcrawl{secrets.token_hex(4)}"
        self._post_done: set[_FormKey | _OpKey] = set()
        self._post_summary: PostSummary | None = None

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

    @property
    def skipped_by_robots(self) -> int:
        """
        Returns:
            int: How many queued URLs the crawler did not fetch because ``robots.txt``
                disallows them (RF-07). A site that disallows ``/`` leaves the crawl with
                the entry page alone, so the scan reports this instead of staying quiet.
        """
        return self._skipped_by_robots

    @property
    def post_summary(self) -> PostSummary | None:
        """
        Returns:
            PostSummary | None: The tally of the ``POST`` phase, or ``None`` when it
                did not run.
        """
        return self._post_summary

    async def discover(self) -> list[Page]:
        """
        Crawl from the seed and return the discovered pages.

        Fetches the seed, enqueues its links, forms, and any sitemap seeds,
        then BFS-fetches the queue until it is empty or ``max_pages`` is
        reached. ``robots.txt`` gates the queue when ``follow_robots`` is on. When the
        ``POST`` phase is on (spec 018) it then submits candidate forms and
        operations, one at a time, resuming the BFS after each answer.

        Returns:
            list[Page]: The discovered pages, seed first, at most ``max_pages``;
                the answers to submissions carry ``method="POST"``.
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

        await self._drain(queue, seen, pages, robots, max_pages)
        if self._post_enabled:
            await self._post_phase(queue, seen, pages, robots, max_pages)
        return pages

    async def _drain(
        self,
        queue: deque[str],
        seen: set[str],
        pages: list[Page],
        robots: robots_mod.Robots,
        max_pages: int,
    ) -> None:
        """
        BFS-fetch the queue until it is empty or ``max_pages`` is reached.

        Args:
            queue (deque[str]): The BFS queue, consumed and appended to in place.
            seen (set[str]): Already-queued URLs, updated in place.
            pages (list[Page]): The pages so far, appended to in place.
            robots (robots_mod.Robots): Parsed ``robots.txt`` for the target.
            max_pages (int): The page cap.
        """
        while queue and len(pages) < max_pages:
            url = queue.popleft()
            if self._config.scan.follow_robots and not robots.can_fetch(self._user_agent, url):
                self._skipped_by_robots += 1
                continue
            page = await self._fetch(url)
            pages.append(page)
            self._enqueue_links(page, seen, queue)
            self._collect_and_enqueue_forms(page, seen, queue)

    async def _post_phase(
        self,
        queue: deque[str],
        seen: set[str],
        pages: list[Page],
        robots: robots_mod.Robots,
        max_pages: int,
    ) -> None:
        """
        Submit candidate forms and operations one at a time (spec 018).

        Each answer is appended as a ``method="POST"`` page, its links and forms
        are enqueued, and the ``GET`` queue is drained before the next candidate, so
        a multi-step flow is followed and a form first seen on an answer joins the
        candidates. Stops at ``max_post_submissions`` or ``max_pages``.

        Args:
            queue (deque[str]): The BFS queue, empty on entry.
            seen (set[str]): Already-queued URLs, updated in place.
            pages (list[Page]): The pages so far, appended to in place.
            robots (robots_mod.Robots): Parsed ``robots.txt`` for the target.
            max_pages (int): The page cap, shared with the ``GET`` crawl.
        """
        summary = PostSummary()
        self._post_summary = summary
        submitted = 0
        while submitted < self._post_cap and len(pages) < max_pages:
            candidate = next(self._pending(robots, summary), None)
            if candidate is None:
                break
            if isinstance(candidate, ApiOperation):
                self._post_done.add(_op_key(candidate))
                page = await self._submit_operation(candidate)
                summary.operations += 1
            else:
                self._post_done.add(_form_key(candidate))
                page = await self._submit_form(candidate)
                summary.forms += 1
            submitted += 1
            pages.append(page)
            self._enqueue_links(page, seen, queue)
            self._collect_and_enqueue_forms(page, seen, queue)
            await self._drain(queue, seen, pages, robots, max_pages)
        summary.over_cap = sum(1 for _ in self._pending(robots, summary))

    def _pending(
        self, robots: robots_mod.Robots, summary: PostSummary
    ) -> Iterator[Form | ApiOperation]:
        """
        Yield the not-yet-submitted candidates: forms in inventory order, then operations.

        The inventory is read afresh on every call, so a form first seen on an answer
        joins. A ``POST`` form or operation that cannot be submitted (not urlencoded or
        multipart, a file input, an auth / search / logout / destructive form, an unsafe
        operation, or disallowed by ``robots.txt``) is marked done and tallied once as
        skipped; ``GET`` forms are not counted at all.

        Args:
            robots (robots_mod.Robots): Parsed ``robots.txt`` for the target.
            summary (PostSummary): Tally of skips, updated in place.

        Yields:
            Form | ApiOperation: The next candidate, without marking it done.
        """
        for form in tuple(self._forms.values()):
            key = _form_key(form)
            if key in self._post_done:
                continue
            if form.method != "POST":
                self._post_done.add(key)
            elif not self._form_eligible(form, robots):
                self._post_done.add(key)
                summary.skipped += 1
            else:
                yield form
        for op in self._post_ops:
            op_key = _op_key(op)
            if op_key in self._post_done:
                continue
            if looks_unsafe_operation(op) or not self._robots_allow(robots, op.url):
                self._post_done.add(op_key)
                summary.skipped += 1
            else:
                yield op

    def _form_eligible(self, form: Form, robots: robots_mod.Robots) -> bool:
        """
        Args:
            form (Form): A ``POST`` form from the inventory.
            robots (robots_mod.Robots): Parsed ``robots.txt`` for the target.

        Returns:
            bool: ``True`` when the form may be submitted: urlencoded or multipart, no
                file input, a CSRF-style candidate (not auth / search), not
                destructive or a logout, and allowed by ``robots.txt``.
        """
        return (
            form.enctype in (_URLENCODED, _MULTIPART)
            and not any(field.type == "file" for field in form.fields)
            and is_candidate(form)
            and not is_destructive_form(form)
            and not is_logout(form.action)
            and self._robots_allow(robots, form.action)
        )

    def _robots_allow(self, robots: robots_mod.Robots, url: str) -> bool:
        """
        Args:
            robots (robots_mod.Robots): Parsed ``robots.txt`` for the target.
            url (str): The URL to be submitted to.

        Returns:
            bool: ``True`` unless ``follow_robots`` is on and ``robots.txt`` disallows it.
        """
        return not self._config.scan.follow_robots or robots.can_fetch(self._user_agent, url)

    async def _submit_form(self, form: Form) -> Page:
        """
        ``POST`` ``form`` with its defaults and the marker.

        Args:
            form (Form): The candidate form.

        Returns:
            Page: The answer (``method="POST"``), or a failed page on a transport or
                scope error.
        """
        pairs = form_body(form, sentinel=self._marker)
        try:
            if form.enctype == _MULTIPART:
                # text-only multipart: a part with no filename is a plain field
                files: list[tuple[str, tuple[str | None, str | bytes, str | None]]] = []
                for name, value in pairs:
                    part: tuple[str | None, str | bytes, str | None] = (None, value, None)
                    files.append((name, part))
                response = await self._http.request("POST", form.action, files=files)
            else:
                # httpx takes only a mapping for ``data=``; a pre-encoded body keeps the
                # order and any repeated name
                response = await self._http.request(
                    "POST",
                    form.action,
                    content=urlencode(pairs),
                    headers={"Content-Type": _URLENCODED},
                )
        except (RequestFailed, OutOfScopeError) as exc:
            return Page.failed(form.action, str(exc), method="POST")
        return Page.from_response(response, method="POST")

    async def _submit_operation(self, op: ApiOperation) -> Page:
        """
        ``POST`` an ``--openapi`` operation with its synthesised body.

        Args:
            op (ApiOperation): The candidate operation.

        Returns:
            Page: The answer (``method="POST"``), or a failed page on a transport or
                scope error.
        """
        headers: dict[str, str] = {}
        content: str | None = None
        if op.body_json is not None:
            content, headers["Content-Type"] = op.body_json, "application/json"
        elif op.body_fields:
            content, headers["Content-Type"] = urlencode(op.body_fields), _URLENCODED
        try:
            response = await self._http.request(
                "POST",
                op.url,
                params=list(op.query) or None,
                content=content,
                headers=headers or None,
            )
        except (RequestFailed, OutOfScopeError) as exc:
            return Page.failed(op.url, str(exc), method="POST")
        return Page.from_response(response, method="POST")

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


def _form_key(form: Form) -> _FormKey:
    """
    Args:
        form (Form): A parsed form.

    Returns:
        _FormKey: ``(method, action, field names)`` — the identity the inventory uses.
    """
    return (form.method, form.action, tuple(field.name for field in form.fields))


def _op_key(op: ApiOperation) -> _OpKey:
    """
    Args:
        op (ApiOperation): An imported operation.

    Returns:
        _OpKey: ``(method, url template, operation id)`` — one submission per operation.
    """
    return (op.method, op.url_template, op.operation_id)


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
