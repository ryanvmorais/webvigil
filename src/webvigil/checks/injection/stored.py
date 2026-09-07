"""The stored / persistent-XSS pass: inject markers, re-crawl, correlate (spec 008).

Run by the orchestrator (``_inject_stored``) when the scan is Active, ``injection.xss.stored``
is selected, and ``[injection] stored_xss`` is on (ADR-1). Two phases:

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

_STORED_REFETCH_CAP = 60
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
    """Form points before query points, each group in ``enumerate_points`` order (RF-04)."""
    forms = [p for p in points if p.source == "form"]
    queries = [p for p in points if p.source != "form"]
    return forms + queries


def _detect(
    markers: dict[str, StoredMarker],
    recrawled: list[Page],
    pre: dict[str, str],
) -> list[InjectionHit]:
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
