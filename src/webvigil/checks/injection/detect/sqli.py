"""
SQL-injection detectors: error-based, boolean-based blind, time-based blind (RF-09).

All three compare against the point's shared baseline and confirm their signal
before emitting a hit (RF-13).
"""

from __future__ import annotations

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx, normalize_body
from webvigil.checks.injection.detect._diff import ratio, status_split, two_sided_split
from webvigil.checks.injection.models import Baseline, InjectionHit, InjectionPoint
from webvigil.core.findings import Confidence, Severity
from webvigil.http.client import Response

_ERROR_ID = "injection.sqli.error-based"
_BOOLEAN_ID = "injection.sqli.boolean-based"
_TIME_ID = "injection.sqli.time-based"

_GAP = 0.90  # FALSE-vs-baseline ceiling — the page-stability guard reuses it

# A form whose field ships empty gives the TRUE payload no row to match, so TRUE and FALSE
# return the same page (issue #143). The boolean detector then seeds the field: a digit for an
# id-looking name, and one letter otherwise (it matches a substring search on most rows).
_SEED_ID = "1"
_SEED_TEXT = "a"
_ID_NAME_SUFFIXES = ("id", "num", "number")


def _point_evidence(point: InjectionPoint) -> tuple[str, str]:
    """
    Args:
        point (InjectionPoint): The point under test.

    Returns:
        tuple[str, str]: The ``("Injection point", ...)`` evidence pair.
    """
    return ("Injection point", f"{point.method} {point.base_url} — parameter '{point.param}'")


async def detect_error(
    point: InjectionPoint, baseline: Baseline, ctx: DetectCtx
) -> list[InjectionHit]:
    """
    Error-based: break the quoting and look for a DBMS parser error absent from the baseline.

    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response.
        ctx (DetectCtx): The budget-aware send context.

    Returns:
        list[InjectionHit]: A single ``sqli-error`` hit naming the DBMS, or
            empty.
    """
    for probe in payloads.SQLI_ERROR:
        response = await ctx.send(point, point.original + probe)
        if response is None:
            break
        for dbms, pattern in payloads.SQL_ERROR_SIGNATURES:
            if pattern.search(payloads.head(response.text)) and not pattern.search(
                payloads.head(baseline.raw_body)
            ):
                match = pattern.search(payloads.head(response.text))
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


def _seed_for(point: InjectionPoint) -> str:
    """
    Args:
        point (InjectionPoint): A point whose current value is empty.

    Returns:
        str: A plausible value for the field, so the TRUE payload can match a row.
    """
    if point.param.lower().endswith(_ID_NAME_SUFFIXES):
        return _SEED_ID
    return _SEED_TEXT


def _split(baseline: Baseline, true_r: Response, false_r: Response) -> str | None:
    """
    Args:
        baseline (Baseline): The response the TRUE payload should track.
        true_r (Response): The TRUE-payload response.
        false_r (Response): The FALSE-payload response.

    Returns:
        str | None: ``"body"`` when the pages diverge (spec 006), ``"status"`` when they are
            the same page in another status class (issue #143), or ``None`` for no split.
    """
    if two_sided_split(baseline.norm_body, true_r.text, false_r.text):
        return "body"
    if status_split(
        baseline.status,
        baseline.norm_body,
        true_r.status_code,
        true_r.text,
        false_r.status_code,
    ):
        return "status"
    return None


async def _boolean_pairs(
    point: InjectionPoint, baseline: Baseline, value: str, ctx: DetectCtx
) -> list[InjectionHit]:
    """
    Run the boolean pairs on top of ``value`` and confirm a split before emitting.

    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): The response to ``value`` alone, the anchor for the split.
        value (str): What the payloads are appended to: the point's own value, or a seed.
        ctx (DetectCtx): The budget-aware send context.

    Returns:
        list[InjectionHit]: A single ``sqli-boolean`` hit, or empty.
    """
    for true_p, false_p in payloads.SQLI_BOOLEAN_PAIRS:
        true_r = await ctx.send(point, value + true_p)
        false_r = await ctx.send(point, value + false_p)
        if true_r is None or false_r is None:
            return []
        kind = _split(baseline, true_r, false_r)
        if kind is None:
            continue

        # The page must be stable between two identical requests, or the split is noise.
        restated = await ctx.send(point, value)
        if (
            restated is None
            or restated.status_code // 100 != baseline.status // 100
            or ratio(baseline.norm_body, normalize_body(restated.text)) < _GAP
        ):
            return []

        # Confirm: the same pair must reproduce the split.
        true2_r = await ctx.send(point, value + true_p)
        false2_r = await ctx.send(point, value + false_p)
        if true2_r is None or false2_r is None:
            return []
        if _split(baseline, true2_r, false2_r) is None:
            continue

        evidence = [
            _point_evidence(point),
            ("TRUE payload", value + true_p),
            ("FALSE payload", value + false_p),
            (
                "Response similarity",
                f"TRUE {ratio(baseline.norm_body, normalize_body(true_r.text)):.2f} vs "
                f"FALSE {ratio(baseline.norm_body, normalize_body(false_r.text)):.2f} "
                "(baseline = 1.00)",
            ),
        ]
        if kind == "status":
            evidence.append(
                (
                    "Status",
                    f"TRUE {true_r.status_code} vs FALSE {false_r.status_code} "
                    f"(baseline {baseline.status})",
                )
            )
        if value != point.original:
            evidence.append(("Seeded value", f"{value!r} (the field is empty by default)"))
        return [
            InjectionHit(
                kind="sqli-boolean",
                check_id=_BOOLEAN_ID,
                method=point.method,
                url=point.base_url,
                param=point.param,
                severity=Severity.HIGH,
                # Pages that only differ by status are a thinner signal than pages that differ.
                confidence=Confidence.HIGH if kind == "body" else Confidence.MEDIUM,
                title=f"SQL injection (boolean-based blind) via '{point.param}'",
                payload=value + true_p,
                evidence=tuple(evidence),
            )
        ]
    return []


async def detect_boolean(
    point: InjectionPoint, baseline: Baseline, ctx: DetectCtx
) -> list[InjectionHit]:
    """
    Boolean-based blind: find a pair where TRUE matches the baseline and FALSE diverges.

    FALSE diverges when its body differs from the baseline's, or when it answers in another
    status class while the body is the same page. Guards against a noisy page: re-checks page
    stability, then re-runs the same pair to confirm the split reproduces before emitting.

    A field that ships empty gives TRUE no row to match, so both payloads return the same
    page. When the pairs find nothing on such a point, they run again on a seeded value
    (issue #143), unless the seed leaves the page as the empty value had it.

    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response.
        ctx (DetectCtx): The budget-aware send context.

    Returns:
        list[InjectionHit]: A single ``sqli-boolean`` hit, or empty.
    """
    hits = await _boolean_pairs(point, baseline, point.original, ctx)
    if hits or point.original:
        return hits

    seed = _seed_for(point)
    seeded = await ctx.send(point, seed)
    if seeded is None:
        return []
    if seeded.status_code // 100 == baseline.status // 100 and (
        ratio(baseline.norm_body, normalize_body(seeded.text)) >= _GAP
    ):
        return []  # the seed changed nothing: TRUE would have no more to match than before
    seeded_baseline = Baseline(
        status=seeded.status_code,
        raw_body=seeded.text,
        norm_body=normalize_body(seeded.text),
        length=len(seeded.text),
        elapsed_ms=seeded.elapsed_ms,
    )
    return await _boolean_pairs(point, seeded_baseline, seed, ctx)


async def detect_time(
    point: InjectionPoint, baseline: Baseline, ctx: DetectCtx
) -> list[InjectionHit]:
    """
    Time-based blind: a payload that sleeps ``delay`` seconds must slow the response.

    Confirms by re-running at half the delay and checking the response time
    scales with the request rather than staying at the full delay.

    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response, for the timing floor.
        ctx (DetectCtx): The budget-aware send context; ``ctx.delay_s`` is the
            requested delay.

    Returns:
        list[InjectionHit]: A single ``sqli-time`` hit (HIGH confidence, or
            MEDIUM when the confirmation request was denied by the budget), or
            empty.
    """
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
