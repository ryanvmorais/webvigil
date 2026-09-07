"""The active-injection pass: enumerate points, baseline each, fan the detectors (RF-12).

Run by the orchestrator when the scan is Active and at least one ``injection.*`` check is
selected (ADR-1, ADR-2). Owns the one shared :class:`ActiveBudget` and the one baseline per
point; the six checks only filter the resulting :class:`InjectionHit`s.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from webvigil.checks.injection.detect import DetectCtx, normalize_body
from webvigil.checks.injection.detect import redirect as redirect_detect
from webvigil.checks.injection.detect import sqli as sqli_detect
from webvigil.checks.injection.detect import ssrf as ssrf_detect
from webvigil.checks.injection.detect import traversal as traversal_detect
from webvigil.checks.injection.detect import xss as xss_detect
from webvigil.checks.injection.models import (
    ActiveBudget,
    Baseline,
    InjectionHit,
    InjectionPoint,
    InjectionReport,
)
from webvigil.checks.injection.points import (
    build_request,
    enumerate_points,
    is_pathlike,
    is_redirect_name,
    is_urllike,
)
from webvigil.core.config import InjectionSection
from webvigil.core.context import Page
from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.core.target import Target
from webvigil.crawler.forms import Form
from webvigil.http.client import HttpClient, Response

_PER_POINT_REQUEST_CAP = 30
_TIME_BASED_SLEEP_CAP = 8

_Detector = Callable[[InjectionPoint, Baseline, DetectCtx], Awaitable[list[InjectionHit]]]

_DETECTORS: dict[str, _Detector] = {
    "xss": xss_detect.detect,
    "sqli-error": sqli_detect.detect_error,
    "sqli-boolean": sqli_detect.detect_boolean,
    "sqli-time": sqli_detect.detect_time,
    "traversal": traversal_detect.detect,
    "redirect": redirect_detect.detect,
    "ssrf": ssrf_detect.detect,
}
# ``ssrf`` runs last so its payload set never starves the 006 detectors on a point with an
# unhelpful name; ``_ordered_kinds`` front-loads it to position 0 for a URL-shaped point.
_BASE_ORDER = ("xss", "sqli-error", "sqli-boolean", "traversal", "redirect", "sqli-time", "ssrf")

KIND_BY_CHECK_ID: dict[str, str] = {
    "injection.xss.reflected": "xss",
    "injection.sqli.error-based": "sqli-error",
    "injection.sqli.boolean-based": "sqli-boolean",
    "injection.sqli.time-based": "sqli-time",
    "injection.traversal.path": "traversal",
    "injection.redirect.open": "redirect",
    # spec 009: both SSRF checks are fed by the one "ssrf" detector, which emits
    # kind="ssrf-metadata" / "ssrf-internal" hits the two checks filter on.
    "injection.ssrf.metadata": "ssrf",
    "injection.ssrf.internal": "ssrf",
}


class InjectionScanner:
    """One bounded crafted-request pass over the target's injection points."""

    def __init__(
        self,
        http: HttpClient,
        target: Target,
        config: InjectionSection,
        pages: tuple[Page, ...],
        forms: tuple[Form, ...],
        selected_kinds: set[str],
        *,
        per_point_limit: int = _PER_POINT_REQUEST_CAP,
    ) -> None:
        self._http = http
        self._target = target
        self._config = config
        self._pages = pages
        self._forms = forms
        self.selected_kinds = {
            k for k in selected_kinds if k != "sqli-time" or config.time_based_sqli
        }
        self._budget = ActiveBudget(
            request_limit=config.request_budget,
            per_point_limit=per_point_limit,
            time_based_limit=_TIME_BASED_SLEEP_CAP if config.time_based_sqli else 0,
        )
        self._ctx = DetectCtx(send=self._send, delay_s=config.time_based_delay_s, host=target.host)

    async def run(self) -> InjectionReport:
        points, warnings = enumerate_points(
            self._pages, self._forms, max_points=self._config.max_injection_points
        )
        report = InjectionReport(warnings=list(warnings))
        for point in points:
            if self._budget.exhausted():
                break
            self._budget.start_point()
            baseline = await self._baseline(point)
            if baseline is None:
                continue
            report.points_tested += 1
            for kind in self._ordered_kinds(point):
                hits = await _DETECTORS[kind](point, baseline, self._ctx)
                report.hits.extend(hits)
                if self._budget.exhausted():
                    break
        if self._budget.exhausted():
            report.warnings.append(
                f"active injection stopped at the {self._config.request_budget}-request budget"
            )
        return report

    def _ordered_kinds(self, point: InjectionPoint) -> list[str]:
        kinds = [k for k in _BASE_ORDER if k in self.selected_kinds]
        for predicate, kind in (
            (is_pathlike, "traversal"),
            (is_redirect_name, "redirect"),
            (is_urllike, "ssrf"),
        ):
            if predicate(point) and kind in kinds:
                kinds.remove(kind)
                kinds.insert(0, kind)
        return kinds

    async def _baseline(self, point: InjectionPoint) -> Baseline | None:
        response = await self._send(point, point.original)
        if response is None:
            return None
        return Baseline(
            status=response.status_code,
            raw_body=response.text,
            norm_body=normalize_body(response.text),
            length=len(response.text),
            elapsed_ms=response.elapsed_ms,
        )

    async def _send(
        self, point: InjectionPoint, value: str, *, time_based: bool = False
    ) -> Response | None:
        if not (self._budget.take_time_based() if time_based else self._budget.take()):
            return None
        method, url, params, data = build_request(point, value)
        try:
            return await self._http.request(
                method, url, params=params or None, data=data, crafted=True
            )
        except (RequestFailed, OutOfScopeError):
            return None
