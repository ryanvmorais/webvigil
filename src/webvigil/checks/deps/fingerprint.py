"""
The dependency fingerprint pass (spec 004, RF-01..RF-05).

Runs in the orchestrator, not as a check (ADR-1). Given the crawled pages and
the shared HTTP client it: collects referenced script/style resources, fetches
the in-scope ones (bounded, best-effort), and applies the vendored Retire.js
rules to every source — the resource URL, its body, and the page's inline
``<script>`` text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin

from selectolax.parser import HTMLParser

from webvigil.checks.deps.rules import RetireJsRules
from webvigil.core.context import Detection, Page
from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.core.target import Target, normalize_url
from webvigil.core.technology import DetectionMethod
from webvigil.http.client import HttpClient

_MAX_FETCHES = 50
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
        raw: list[Detection] = []

        in_scope_queue: list[str] = []
        seen_resources: set[str] = set()

        for page in pages:
            if not (page.ok and page.is_html and page.text):
                continue
            tree = HTMLParser(page.text)
            raw.extend(self._from_inline_scripts(tree, page.url))
            for url in self._resource_urls(tree, page.url):
                if url in seen_resources:
                    continue
                seen_resources.add(url)
                if not self._target.in_scope(url):
                    raw.extend(self._rules.identify(url=url))  # CDN: URL only, never fetched
                elif normalize_url(url) not in crawled:
                    in_scope_queue.append(url)

        if len(in_scope_queue) > self._max_fetches:
            result.warnings.append(
                f"dependency fingerprinting stopped at {self._max_fetches} resource fetches "
                f"({len(in_scope_queue)} referenced)"
            )
            in_scope_queue = in_scope_queue[: self._max_fetches]

        for url in in_scope_queue:
            body = await self._fetch(url)
            raw.extend(self._rules.identify(url=url, body=body))

        result.detections = _dedupe(raw)
        return result

    def _resource_urls(self, tree: HTMLParser, base: str) -> list[str]:
        """
        Args:
            tree (HTMLParser): The parsed page.
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
                urls.append(urljoin(base, value))
        return urls

    def _from_inline_scripts(self, tree: HTMLParser, page_url: str) -> list[Detection]:
        """
        Args:
            tree (HTMLParser): The parsed page.
            page_url (str): The page URL, recorded as the detection source.

        Returns:
            list[Detection]: Libraries identified from the text of every inline
                ``<script>`` (those with no ``src``).
        """
        found: list[Detection] = []
        for node in tree.css("script"):
            if node.attributes.get("src"):
                continue
            text = node.text(deep=False)
            if text and text.strip():
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


def _dedupe(detections: list[Detection]) -> list[Detection]:
    """
    Collapse to one detection per ``(name, version)``.

    A concrete version wins over a version-less one, and a stronger detection
    method (hash > SRI > filename/content > URI) wins on ties.

    Args:
        detections (list[Detection]): The raw detections from every source.

    Returns:
        list[Detection]: The winners, sorted by name then version.
    """
    best: dict[tuple[str, str | None], Detection] = {}
    for detection in detections:
        key = (detection.name, detection.version)
        current = best.get(key)
        if current is None or _rank(detection.method) > _rank(current.method):
            best[key] = detection
    # Drop a version-less detection when the same library also has a versioned one.
    versioned = {name for (name, version) in best if version is not None}
    return sorted(
        (d for (name, version), d in best.items() if version is not None or name not in versioned),
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
