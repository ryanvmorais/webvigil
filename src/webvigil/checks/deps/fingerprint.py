"""
The dependency fingerprint pass (spec 004, RF-01..RF-05).

Runs in the orchestrator, not as a check (ADR-1). Given the crawled pages and
the shared HTTP client it: collects referenced script/style resources, fetches
the in-scope ones (bounded, best-effort), and applies the vendored Retire.js
rules to every source — the resource URL, its body, and the page's inline
``<script>`` text.

The pages come from the scanned site, which decides how many inline scripts and resource
references they carry. The pass reads each distinct inline script once, up to
``_MAX_INLINE_CHARS`` characters of them in a scan, and examines up to ``_MAX_RESOURCE_URLS``
distinct resource URLs; past either limit it stops reading that source and warns. Each source can
name many libraries and versions, so detections are merged as they are found and the pass keeps
up to ``_MAX_LIBRARY_VERSIONS`` distinct ``(name, version)`` pairs; it warns when it drops one.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field

from selectolax.lexbor import LexborHTMLParser

from webvigil.checks.deps.rules import _BODY_MAX, RetireJsRules
from webvigil.core.context import Detection, Page
from webvigil.core.destination import may_request
from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.core.html import parse_html
from webvigil.core.target import Target, normalize_url
from webvigil.core.technology import DetectionMethod
from webvigil.core.urls import resolve_url
from webvigil.crawler.safety import is_unsafe_url
from webvigil.http.client import HttpClient

_MAX_FETCHES = 50
# Characters of distinct inline scripts the content patterns read in one scan (each script is
# read up to the rules' head cap), and distinct script / stylesheet URLs examined in one scan.
_MAX_INLINE_CHARS = 4 * 1024 * 1024
_MAX_RESOURCE_URLS = 1000
# Distinct (library, version) pairs one scan keeps. Each becomes a technology, possibly a finding
# and, with ``[deps] osv_online``, an OSV.dev query; a real site loads a few dozen at most.
_MAX_LIBRARY_VERSIONS = 200
_RESOURCE_ATTRS = (("script", "src"), ("link", "href"))


@dataclass
class FingerprintResult:
    """
    The output of one fingerprint pass.

    Attributes:
        detections (list[Detection]): The de-duplicated libraries found.
            Defaults to empty.
        warnings (list[str]): Non-fatal notices (e.g. the fetch cap was hit).
            Defaults to empty.
    """

    detections: list[Detection] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class Fingerprinter:
    """Applies the Retire.js rules to a crawl's resources and inline scripts."""

    def __init__(
        self,
        http: HttpClient,
        target: Target,
        rules: RetireJsRules,
        *,
        max_fetches: int = _MAX_FETCHES,
    ) -> None:
        """
        Args:
            http (HttpClient): The shared, scope-guarded HTTP client.
            target (Target): The normalized target and its scope rule.
            rules (RetireJsRules): The compiled Retire.js matchers.
            max_fetches (int): Cap on extra in-scope resource fetches. Defaults
                to ``_MAX_FETCHES``.
        """
        self._http = http
        self._target = target
        self._rules = rules
        self._max_fetches = max_fetches

    async def scan(self, pages: tuple[Page, ...]) -> FingerprintResult:
        """
        Fingerprint the libraries reachable from a crawl.

        Reads each HTML page's inline scripts and resource references, matches
        out-of-scope (CDN) resources by URL only, fetches the in-scope ones not
        already crawled (up to ``max_fetches``), and matches their bodies.

        Args:
            pages (tuple[Page, ...]): The crawled pages.

        Returns:
            FingerprintResult: The de-duplicated detections and any warnings.
        """
        result = FingerprintResult()
        crawled = {normalize_url(p.url) for p in pages}
        found = _Found()

        in_scope_queue: list[str] = []
        seen_resources: set[str] = set()
        inline = _InlineBudget()
        urls_capped = False

        for page in pages:
            if not (page.ok and page.is_html and page.text):
                continue
            tree = parse_html(page.text)
            found.add(self._from_inline_scripts(tree, page.url, inline))
            for url in self._resource_urls(tree, page.url):
                if url in seen_resources:
                    continue
                if len(seen_resources) >= _MAX_RESOURCE_URLS:
                    urls_capped = True
                    break
                seen_resources.add(url)
                # a CDN, or a resource named like a logout or a destructive action: the URL
                # alone is read, never fetched
                if not may_request(self._target, url) or is_unsafe_url(url):
                    found.add(self._rules.identify(url=url))
                elif normalize_url(url) not in crawled:
                    in_scope_queue.append(url)

        if urls_capped:
            result.warnings.append(
                "dependency fingerprinting stopped at "
                f"{_MAX_RESOURCE_URLS} distinct resource URLs"
            )
        if inline.exhausted:
            result.warnings.append(
                "dependency fingerprinting stopped reading inline scripts after "
                f"{_MAX_INLINE_CHARS} characters"
            )
        if len(in_scope_queue) > self._max_fetches:
            result.warnings.append(
                f"dependency fingerprinting stopped at {self._max_fetches} resource fetches "
                f"({len(in_scope_queue)} referenced)"
            )
            in_scope_queue = in_scope_queue[: self._max_fetches]

        for url in in_scope_queue:
            body = await self._fetch(url)
            found.add(self._rules.identify(url=url, body=body))

        if found.capped:
            result.warnings.append(
                "dependency fingerprinting stopped at "
                f"{_MAX_LIBRARY_VERSIONS} distinct library versions"
            )
        result.detections = found.winners()
        return result

    def _resource_urls(self, tree: LexborHTMLParser, base: str) -> list[str]:
        """
        Args:
            tree (LexborHTMLParser): The parsed page.
            base (str): The page URL, for resolving relative references.

        Returns:
            list[str]: Absolute URLs of ``<script src>`` and relevant
                ``<link href>`` (stylesheet / preload / modulepreload)
                resources.
        """
        urls: list[str] = []
        for tag, attr in _RESOURCE_ATTRS:
            for node in tree.css(tag):
                value = node.attributes.get(attr)
                if not value:
                    continue
                if tag == "link":
                    rel = (node.attributes.get("rel") or "").lower()
                    if not any(k in rel for k in ("stylesheet", "preload", "modulepreload")):
                        continue
                if (url := resolve_url(base, value)) is not None:
                    urls.append(url)
        return urls

    def _from_inline_scripts(
        self, tree: LexborHTMLParser, page_url: str, budget: _InlineBudget
    ) -> list[Detection]:
        """
        Args:
            tree (LexborHTMLParser): The parsed page.
            page_url (str): The page URL, recorded as the detection source.
            budget (_InlineBudget): What is left to read in this scan, updated in place.

        Returns:
            list[Detection]: Libraries identified from the text of every inline
                ``<script>`` (those with no ``src``) not read on an earlier page, until the
                budget runs out.
        """
        found: list[Detection] = []
        for node in tree.css("script"):
            if budget.exhausted:
                break
            if node.attributes.get("src"):
                continue
            text = node.text(deep=False)
            if text and text.strip() and budget.admit(text):
                found.extend(self._rules.identify(url=page_url, body=text))
        return found

    async def _fetch(self, url: str) -> str | None:
        """
        Args:
            url (str): The in-scope resource URL to fetch.

        Returns:
            str | None: The response body, or ``None`` on a transport failure,
                a scope refusal, or a >= 400 status.
        """
        try:
            response = await self._http.get(url)
        except (RequestFailed, OutOfScopeError):
            return None
        if response.status_code >= 400:
            return None
        return response.text


@dataclass
class _InlineBudget:
    """
    What one scan still reads of inline scripts.

    Attributes:
        left (int): Characters the content patterns may still read. Defaults to
            ``_MAX_INLINE_CHARS``.
        seen (set[bytes]): Digests of the scripts already read. Defaults to empty.
        exhausted (bool): Whether a script was turned away for lack of budget. Defaults to
            ``False``.
    """

    left: int = _MAX_INLINE_CHARS
    seen: set[bytes] = field(default_factory=set)
    exhausted: bool = False

    def admit(self, text: str) -> bool:
        """
        Args:
            text (str): An inline script.

        Returns:
            bool: ``True`` when the script is new in this scan and fits what is left; its
                characters (up to the rules' head cap) are then taken from the budget.
        """
        digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).digest()
        if digest in self.seen:
            return False
        cost = min(len(text), _BODY_MAX)
        if cost > self.left:
            self.exhausted = True
            return False
        self.seen.add(digest)
        self.left -= cost
        return True


@dataclass
class _Found:
    """
    The detections of one scan, one per ``(name, version)``, merged as they are found.

    A stronger detection method (hash > SRI > filename/content > URI) replaces a weaker one of the
    same pair. Up to ``_MAX_LIBRARY_VERSIONS`` pairs are kept; a new pair past that is dropped.

    Attributes:
        best (dict[tuple[str, str | None], Detection]): The detection kept per pair. Defaults to
            empty.
        capped (bool): Whether a pair was dropped for the cap. Defaults to ``False``.
    """

    best: dict[tuple[str, str | None], Detection] = field(default_factory=dict)
    capped: bool = False

    def add(self, detections: Iterable[Detection]) -> None:
        """
        Merge the detections of one source into those kept.

        Args:
            detections (Iterable[Detection]): Detections from one source.
        """
        for detection in detections:
            key = (detection.name, detection.version)
            current = self.best.get(key)
            if current is None:
                if len(self.best) >= _MAX_LIBRARY_VERSIONS:
                    self.capped = True
                    continue
                self.best[key] = detection
            elif _rank(detection.method) > _rank(current.method):
                self.best[key] = detection

    def winners(self) -> list[Detection]:
        """
        The detections the scan reports.

        Returns:
            list[Detection]: The kept detections, sorted by name then version, without the
                version-less one of a library that also has a versioned one.
        """
        versioned = {name for (name, version) in self.best if version is not None}
        return sorted(
            (
                d
                for (name, version), d in self.best.items()
                if version is not None or name not in versioned
            ),
            key=lambda d: (d.name, d.version or ""),
        )


def _rank(method: DetectionMethod) -> int:
    """
    Args:
        method (DetectionMethod): A detection method.

    Returns:
        int: Its trust rank — higher is stronger, used to break de-dup ties.
    """
    order = {
        DetectionMethod.HASH: 4,
        DetectionMethod.SRI: 3,
        DetectionMethod.FILENAME: 2,
        DetectionMethod.FILECONTENT: 2,
        DetectionMethod.URI: 1,
    }
    return order[method]
