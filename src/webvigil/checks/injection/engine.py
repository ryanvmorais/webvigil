"""
The active-injection pass: enumerate points, baseline each, fan the detectors (RF-12).

Run by the orchestrator when the scan is Active and at least one ``injection.*``
check is selected (ADR-1, ADR-2). Owns the one shared :class:`ActiveBudget` and
the one baseline per point; the checks only filter the resulting
:class:`InjectionHit`s.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from webvigil.checks.injection.detect import DetectCtx, normalize_body
from webvigil.checks.injection.detect import cmdi as cmdi_detect
from webvigil.checks.injection.detect import redirect as redirect_detect
from webvigil.checks.injection.detect import sqli as sqli_detect
from webvigil.checks.injection.detect import ssrf as ssrf_detect
from webvigil.checks.injection.detect import ssti as ssti_detect
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
    is_commandlike,
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

# Raised from 30 (spec 006) to 35 in spec 011: the cmdi + ssti detector families now share a
# point's budget (spec 011 Resolved decision 6 — measured against the fixture; +5 is enough
# for the front-loaded ssti/cmdi canary without letting the slow time-based detectors run on
# a point that would otherwise stop before them).
_PER_POINT_REQUEST_CAP = 35
_TIME_BASED_SLEEP_CAP = 8

_Detector = Callable[[InjectionPoint, Baseline, DetectCtx], Awaitable[list[InjectionHit]]]

_DETECTORS: dict[str, _Detector] = {
    "xss": xss_detect.detect,
    "sqli-error": sqli_detect.detect_error,
    "sqli-boolean": sqli_detect.detect_boolean,
    "sqli-time": sqli_detect.detect_time,
    "traversal": traversal_detect.detect,
    "redirect": redirect_detect.detect,
    "ssti": ssti_detect.detect,
    "cmdi": cmdi_detect.detect,
    "ssrf": ssrf_detect.detect,
}
# ``ssti`` is broad and ``cmdi`` / ``ssrf`` carry slow or large payload sets, so all three
# sit near the end where they cannot starve the fast 006 detectors on a point with an
# unhelpful name; ``_ordered_kinds`` front-loads each to position 0 for a point its
# heuristic matches.
_BASE_ORDER = (
    "xss",
    "sqli-error",
    "sqli-boolean",
    "traversal",
    "redirect",
    "ssti",
    "sqli-time",
    "cmdi",
    "ssrf",
)

KIND_BY_CHECK_ID: dict[str, str] = {
    "injection.xss.reflected": "xss",
    "injection.sqli.error-based": "sqli-error",
    "injection.sqli.boolean-based": "sqli-boolean",
    "injection.sqli.time-based": "sqli-time",
    "injection.traversal.path": "traversal",
    "injection.redirect.open": "redirect",
    # spec 011: the "cmdi" detector runs both its echo and time stages internally; the
    # time stage is gated by DetectCtx.time_based_cmdi, not by dropping a kind.
    "injection.cmdi.os": "cmdi",
    "injection.ssti": "ssti",
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
        """
        Args:
            http (HttpClient): The shared, scope-guarded HTTP client.
            target (Target): The normalized target.
            config (InjectionSection): The ``[injection]`` tuning.
            pages (tuple[Page, ...]): The crawled pages.
            forms (tuple[Form, ...]): The parsed form inventory.
            selected_kinds (set[str]): Detector kinds to run, derived from the
                selected checks; ``sqli-time`` is dropped when
                ``time_based_sqli`` is off.
            per_point_limit (int): Cap on requests per injection point. Defaults
                to ``_PER_POINT_REQUEST_CAP``.
        """
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
            time_based_limit=(
                _TIME_BASED_SLEEP_CAP if (config.time_based_sqli or config.time_based_cmdi) else 0
            ),
        )
        self._ctx = DetectCtx(
            send=self._send,
            delay_s=config.time_based_delay_s,
            host=target.host,
            time_based_cmdi=config.time_based_cmdi,
        )

    async def run(self) -> InjectionReport:
        """
        Enumerate points, baseline each, and run the ordered detectors under the budget.

        Returns:
            InjectionReport: The confirmed hits, the point count, and any
                warnings (point cap, budget exhausted).
        """
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
        """
        Order the selected detector kinds for one point.

        Starts from ``_BASE_ORDER`` (``ssrf`` last), then front-loads
        ``traversal`` / ``redirect`` / ``ssrf`` to position 0 when the point's
        name or value matches that detector's heuristic.

        Args:
            point (InjectionPoint): The point under test.

        Returns:
            list[str]: The detector kinds to run, in order.
        """
        kinds = [k for k in _BASE_ORDER if k in self.selected_kinds]
        for predicate, kind in (
            (is_pathlike, "traversal"),
            (is_redirect_name, "redirect"),
            (is_urllike, "ssrf"),
            (is_commandlike, "cmdi"),
            (is_commandlike, "ssti"),
        ):
            if predicate(point) and kind in kinds:
                kinds.remove(kind)
                kinds.insert(0, kind)
        return kinds

    async def _baseline(self, point: InjectionPoint) -> Baseline | None:
        """
        Send the point's original value once and capture it as the differential anchor.

        Args:
            point (InjectionPoint): The point to baseline.

        Returns:
            Baseline | None: The baseline, or ``None`` when the request was
                denied by the budget or failed.
        """
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
        """
        The :class:`~webvigil.checks.injection.detect.Sender` bound into ``DetectCtx``.

        Reserves budget first — time-based requests against the time sub-budget
        — then replays the point with ``value``.

        Args:
            point (InjectionPoint): The point to replay.
            value (str): The value to place in the point's slot.
            time_based (bool): Charge against the time-based sub-budget.
                Defaults to ``False``.

        Returns:
            Response | None: The response, or ``None`` when the budget is spent
                or the request failed.
        """
        if not (self._budget.take_time_based() if time_based else self._budget.take()):
            return None
        method, url, params, data = build_request(point, value)
        try:
            return await self._http.request(
                method, url, params=params or None, data=data, crafted=True
            )
        except (RequestFailed, OutOfScopeError):
            return None
