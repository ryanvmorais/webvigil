"""SQL-injection detectors: error-based, boolean-based blind, time-based blind (RF-09).

All three compare against the point's shared baseline and confirm their signal before
emitting a hit (RF-13).
"""

from __future__ import annotations

from difflib import SequenceMatcher

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx, normalize_body
from webvigil.checks.injection.models import Baseline, InjectionHit, InjectionPoint
from webvigil.core.findings import Confidence, Severity

_ERROR_ID = "injection.sqli.error-based"
_BOOLEAN_ID = "injection.sqli.boolean-based"
_TIME_ID = "injection.sqli.time-based"

_SIMILARITY = 0.95  # TRUE-vs-baseline floor
_GAP = 0.90  # FALSE-vs-baseline ceiling


def _ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).quick_ratio()


def _point_evidence(point: InjectionPoint) -> tuple[str, str]:
    return ("Injection point", f"{point.method} {point.base_url} — parameter '{point.param}'")


async def detect_error(
    point: InjectionPoint, baseline: Baseline, ctx: DetectCtx
) -> list[InjectionHit]:
    for probe in payloads.SQLI_ERROR:
        response = await ctx.send(point, point.original + probe)
        if response is None:
            break
        for dbms, pattern in payloads.SQL_ERROR_SIGNATURES:
            if pattern.search(response.text) and not pattern.search(baseline.raw_body):
                match = pattern.search(response.text)
                quoted = match.group(0) if match else ""
                return [
                    InjectionHit(
                        kind="sqli-error",
                        check_id=_ERROR_ID,
                        method=point.method,
                        url=point.base_url,
                        param=point.param,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        title=f"SQL injection ({dbms}) via the '{point.param}' parameter",
                        payload=point.original + probe,
                        evidence=(
                            _point_evidence(point),
                            ("Payload", point.original + probe),
                            ("Database error", quoted),
                        ),
                    )
                ]
    return []


async def detect_boolean(
    point: InjectionPoint, baseline: Baseline, ctx: DetectCtx
) -> list[InjectionHit]:
    for true_p, false_p in payloads.SQLI_BOOLEAN_PAIRS:
        true_r = await ctx.send(point, point.original + true_p)
        false_r = await ctx.send(point, point.original + false_p)
        if true_r is None or false_r is None:
            return []
        if not _splits(baseline.norm_body, true_r.text, false_r.text):
            continue

        # The page must be stable between two identical requests, or the split is noise.
        restated = await ctx.send(point, point.original)
        if restated is None or _ratio(baseline.norm_body, normalize_body(restated.text)) < _GAP:
            return []

        # Confirm: the same pair must reproduce the split.
        true2_r = await ctx.send(point, point.original + true_p)
        false2_r = await ctx.send(point, point.original + false_p)
        if true2_r is None or false2_r is None:
            return []
        if not _splits(baseline.norm_body, true2_r.text, false2_r.text):
            continue

        return [
            InjectionHit(
                kind="sqli-boolean",
                check_id=_BOOLEAN_ID,
                method=point.method,
                url=point.base_url,
                param=point.param,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title=f"SQL injection (boolean-based blind) via '{point.param}'",
                payload=point.original + true_p,
                evidence=(
                    _point_evidence(point),
                    ("TRUE payload", point.original + true_p),
                    ("FALSE payload", point.original + false_p),
                    (
                        "Response similarity",
                        f"TRUE {_ratio(baseline.norm_body, normalize_body(true_r.text)):.2f} vs "
                        f"FALSE {_ratio(baseline.norm_body, normalize_body(false_r.text)):.2f} "
                        "(baseline = 1.00)",
                    ),
                ),
            )
        ]
    return []


def _splits(baseline_norm: str, true_body: str, false_body: str) -> bool:
    return (
        _ratio(baseline_norm, normalize_body(true_body)) >= _SIMILARITY
        and _ratio(baseline_norm, normalize_body(false_body)) <= _GAP
    )


async def detect_time(
    point: InjectionPoint, baseline: Baseline, ctx: DetectCtx
) -> list[InjectionHit]:
    delay = ctx.delay_s
    threshold_ms = (delay - 1) * 1000
    for dbms, template in payloads.SQLI_TIME:
        control = await ctx.send(point, point.original + template.format(d=0))
        if control is None:
            return []
        slow = await ctx.send(point, point.original + template.format(d=delay), time_based=True)
        if slow is None:
            return []
        floor_ms = max(control.elapsed_ms, baseline.elapsed_ms)
        if slow.elapsed_ms - floor_ms < threshold_ms:
            continue

        half = max(1, delay // 2)
        confirm = await ctx.send(point, point.original + template.format(d=half), time_based=True)
        confidence = Confidence.HIGH
        if confirm is None:
            confidence = Confidence.MEDIUM
        else:
            confirm_delta = confirm.elapsed_ms - floor_ms
            # A real time injection scales with the requested delay: the half-delay
            # response lands in a band around `half` seconds, not still up at `delay`.
            if not (half - 1) * 1000 <= confirm_delta <= (half + 2) * 1000:
                continue

        return [
            InjectionHit(
                kind="sqli-time",
                check_id=_TIME_ID,
                method=point.method,
                url=point.base_url,
                param=point.param,
                severity=Severity.HIGH,
                confidence=confidence,
                title=f"SQL injection ({dbms}, time-based blind) via '{point.param}'",
                payload=point.original + template.format(d=delay),
                evidence=(
                    _point_evidence(point),
                    ("Payload", point.original + template.format(d=delay)),
                    (
                        "Timing",
                        f"control {control.elapsed_ms:.0f} ms, injected {slow.elapsed_ms:.0f} ms "
                        f"(delay requested: {delay} s)",
                    ),
                ),
            )
        ]
    return []
