"""
The stored / persistent-XSS pass: inject markers, re-crawl, correlate (spec 008).

Run by the orchestrator (``_inject_stored``) when the scan is Active,
``injection.xss.stored`` is selected, and ``[injection] stored_xss`` is on
(ADR-1). Two phases:

* **A — inject.** One token-tagged marker set per in-scope non-excluded injection point
  (006's ``enumerate_points`` — POST-form points first, query params second).
* **B — re-crawl.** A depth-1 re-crawl from the first crawl's frontier
  (:meth:`Crawler.recrawl`); every re-crawled body is searched for a marker rendered with
  its markup intact in an executable context, on a page other than the one it was submitted
  to.

The pass owns one :class:`ActiveBudget` sized from ``[injection] request_budget`` (Phase A
via ``take()``, Phase B via ``take_recrawl()``); ``_STORED_REFETCH_CAP`` bounds Phase B.
"""

from __future__ import annotations

import secrets

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import xss
from webvigil.checks.injection.models import (
    ActiveBudget,
    InjectionHit,
    InjectionPoint,
    StoredMarker,
    StoredXssReport,
)
from webvigil.checks.injection.points import build_request, enumerate_points
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.core.findings import Confidence, Severity
from webvigil.core.target import Target, normalize_url
from webvigil.crawler.crawler import Crawler
from webvigil.crawler.forms import Form
from webvigil.http.client import HttpClient, Response

# Phase B page budget. Raised from 60 (spec 008) to 120 in spec 014: specs 011-014 each
# added crawlable endpoints and detector families that fuzz a stored sink, so on a target
# that stores every submission (the test fixture's guestbook) the marker's own entry can sit
# past the old cap before the re-crawl reaches it. A real target is bounded by its actual
# link count, and Phase B still respects the shared request_budget, so the ceiling costs
# nothing there. Excess is a warning, not an error.
_STORED_REFETCH_CAP = 120
_PER_POINT_REQUEST_CAP = 30  # mirrors engine._PER_POINT_REQUEST_CAP (Phase A submissions)
_CHECK_ID = "injection.xss.stored"

_Render = tuple[str, str, str, str]  # (page_url, context, matched_payload, page_text)


class StoredXssScanner:
    """One two-phase stored-XSS pass over the target's injection points."""

    def __init__(
        self,
        http: HttpClient,
        target: Target,
        config: ScanConfig,
        pages: tuple[Page, ...],
        forms: tuple[Form, ...],
    ) -> None:
        """
        Args:
            http (HttpClient): The shared, scope-guarded HTTP client.
            target (Target): The normalized target.
            config (ScanConfig): The full scan config; supplies the injection
                budget, the point cap, and ``scan.max_pages`` for the re-crawl.
            pages (tuple[Page, ...]): The first crawl's pages — the Phase-B
                frontier and the "known before injection" baseline.
            forms (tuple[Form, ...]): The parsed form inventory.
        """
        self._http = http
        self._target = target
        self._config = config
        self._pages = pages
        self._forms = forms
        self._budget = ActiveBudget(
            request_limit=config.injection.request_budget,
            per_point_limit=_PER_POINT_REQUEST_CAP,
            time_based_limit=0,
        )

    async def run(self) -> StoredXssReport:
        """
        Run Phase A (inject a marker set per point) then Phase B (re-crawl and correlate).

        Returns early after Phase A when nothing was submitted.

        Returns:
            StoredXssReport: The confirmed stored-XSS hits, the marker and
                re-crawl counts, and any warnings (point cap, budget, re-crawl
                cap).
        """
        points, warnings = enumerate_points(
            self._pages, self._forms, max_points=self._config.injection.max_injection_points
        )
        report = StoredXssReport(warnings=list(warnings))

        # Phase A — one token-tagged marker set per point (POST forms first).
        markers: dict[str, StoredMarker] = {}
        for point in _stored_order(points):
            if self._budget.exhausted():
                break
            self._budget.start_point()
            token = secrets.token_hex(payloads.STORED_TOKEN_BYTES)
            sent: list[str] = []
            for template in payloads.STORED_MARKERS:
                payload = template.format(token=token)
                if await self._submit(point, payload) is None:
                    break
                sent.append(payload)
            if sent:
                markers[token] = StoredMarker(token=token, point=point, payloads=tuple(sent))
        report.markers_submitted = len(markers)
        if not markers:
            return report

        # Phase B — depth-1 re-crawl from the first crawl's frontier.
        frontier = tuple(page.url for page in self._pages if page.ok)
        pre = {normalize_url(page.url): page.text for page in self._pages if page.ok}
        max_fetches = min(_STORED_REFETCH_CAP, max(1, self._config.scan.max_pages))
        recrawled = await Crawler(self._http, self._target, self._config).recrawl(
            frontier, should_fetch=self._budget.take_recrawl, max_fetches=max_fetches
        )
        report.pages_recrawled = len(recrawled)
        if self._budget.exhausted():
            report.warnings.append(
                f"active injection stopped at the {self._budget.request_limit}-request budget"
            )
        if len(recrawled) >= max_fetches:
            report.warnings.append(f"stored-XSS re-crawl stopped at the {max_fetches}-page cap")

        report.hits = _detect(markers, recrawled, pre)
        return report

    async def _submit(self, point: InjectionPoint, payload: str) -> Response | None:
        """
        Phase-A submission: reserve budget, then replay ``point`` with one marker payload.

        Args:
            point (InjectionPoint): The point to inject through.
            payload (str): The concrete marker string (token substituted).

        Returns:
            Response | None: The response, or ``None`` when the budget is spent
                or the request failed.
        """
        if not self._budget.take():
            return None
        method, url, params, data = build_request(point, payload)
        try:
            return await self._http.request(
                method, url, params=params or None, data=data, crafted=True
            )
        except (RequestFailed, OutOfScopeError):
            return None


def _stored_order(points: list[InjectionPoint]) -> list[InjectionPoint]:
    """
    Args:
        points (list[InjectionPoint]): The enumerated points.

    Returns:
        list[InjectionPoint]: Form points before query points, each group in
            ``enumerate_points`` order (RF-04).
    """
    forms = [p for p in points if p.source == "form"]
    queries = [p for p in points if p.source != "form"]
    return forms + queries


def _detect(
    markers: dict[str, StoredMarker],
    recrawled: list[Page],
    pre: dict[str, str],
) -> list[InjectionHit]:
    """
    Correlate each submitted marker against the re-crawled bodies.

    A marker counts only when it appears verbatim in an HTML body it was not in
    before injection, and — for a GET injection point — on a different page than
    the one it was submitted to (that would be reflected, not stored).

    Args:
        markers (dict[str, StoredMarker]): Submitted markers, keyed by token.
        recrawled (list[Page]): The Phase-B pages.
        pre (dict[str, str]): Normalized URL -> body text from the first crawl.

    Returns:
        list[InjectionHit]: One ``xss-stored`` hit per marker that rendered.
    """
    hits: list[InjectionHit] = []
    for marker in markers.values():
        renders: list[_Render] = []
        for page in recrawled:
            if not (page.ok and page.is_html and page.text):
                continue
            known = pre.get(normalize_url(page.url))
            for payload in marker.payloads:
                if payload not in page.text:
                    continue  # not there, or entity-/percent-encoded → safe
                if known is not None and payload in known:
                    continue  # already present before we injected — not our doing
                same_url = normalize_url(page.url) == normalize_url(marker.point.base_url)
                if same_url and marker.point.method != "POST":
                    continue  # same URL as a GET injection point → reflected, not stored
                renders.append((page.url, xss._context(page.text, payload), payload, page.text))
                break
        if renders:
            hits.append(_stored_hit(marker, renders))
    return hits


def _stored_hit(marker: StoredMarker, renders: list[_Render]) -> InjectionHit:
    """
    Build the finding-ready hit for one marker that rendered on one or more pages.

    The hit's location is the injection point (a stable fingerprint, RF-09), not
    the render page; render pages go in the evidence. Confidence is HIGH for an
    off-point render in an html-body / attribute context, MEDIUM otherwise.

    Args:
        marker (StoredMarker): The submitted marker.
        renders (list[_Render]): Where it was found, first render first.

    Returns:
        InjectionHit: The ``xss-stored`` hit.
    """
    first_url, context, payload, text = renders[0]
    extra = len(renders) - 1
    off_point = normalize_url(first_url) != normalize_url(marker.point.base_url)
    confidence = (
        Confidence.HIGH
        if context in ("html body", "attribute") and off_point
        else Confidence.MEDIUM
    )
    rendered_on = first_url + (f"  (+{extra} more page(s))" if extra else "")
    point = marker.point
    return InjectionHit(
        kind="xss-stored",
        check_id=_CHECK_ID,
        method=point.method,
        url=point.base_url,  # the injection point, not the render page — stable fingerprint (RF-09)
        param=point.param,
        severity=Severity.HIGH,
        confidence=confidence,
        title=(
            f"Stored XSS: the '{point.param}' field of {point.method} {point.base_url} "
            f"renders unescaped on {first_url}"
        ),
        payload=payload,
        evidence=(
            ("Injection point", f"{point.method} {point.base_url} — parameter '{point.param}'"),
            ("Marker payload", payload),
            ("Rendered on", rendered_on),
            ("Reflection context", context),
            ("Response snippet", xss._snippet(text, payload)),
        ),
    )
