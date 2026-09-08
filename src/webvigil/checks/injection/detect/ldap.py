"""
LDAP-injection detector — a filter-parser error, or a widened result set (spec 014, RF-08).

The payload reaches an LDAP search filter the application builds from the
parameter. Two signals, both differential:

* an **error probe** appends a filter-breaking metacharacter; a hit needs an
  LDAP-parser error signature in the response, absent from the baseline;
* a **boolean probe** sends an always-matching filter (which widens the result
  set) and an always-failing one (which does not); a hit needs the widen
  differential (:func:`~webvigil.checks.injection.detect._diff.wider_then_same`)
  to reproduce.

WebVigil parses no LDAP itself — it sends the payload and reads the response.
"""

from __future__ import annotations

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx
from webvigil.checks.injection.detect._diff import wider_then_same
from webvigil.checks.injection.models import Baseline, InjectionHit, InjectionPoint
from webvigil.core.findings import Confidence, Severity

_CHECK_ID = "injection.ldap"


async def detect(point: InjectionPoint, baseline: Baseline, ctx: DetectCtx) -> list[InjectionHit]:
    """
    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response; a signature must be absent
            from it.
        ctx (DetectCtx): The budget-aware send context.

    Returns:
        list[InjectionHit]: A single ``ldap`` hit — HIGH for a parser error,
            MEDIUM for a reproduced result-set widen — else empty.
    """
    for probe in payloads.LDAP_ERROR:
        response = await ctx.send(point, point.original + probe)
        if response is None:
            return []
        for pattern in payloads.LDAP_ERROR_SIGNATURES:
            match = pattern.search(response.text)
            if match and not pattern.search(baseline.raw_body):
                return [
                    _hit(
                        point,
                        point.original + probe,
                        Severity.HIGH,
                        Confidence.HIGH,
                        "LDAP injection via the '{param}' parameter (filter error)",
                        ("LDAP error", match.group(0)),
                    )
                ]

    for true_p, false_p in payloads.LDAP_BOOLEAN:
        true_r = await ctx.send(point, true_p)
        false_r = await ctx.send(point, point.original + false_p)
        if true_r is None or false_r is None:
            return []
        if not wider_then_same(baseline.norm_body, baseline.length, true_r.text, false_r.text):
            continue
        # Confirm: the same pair must reproduce the widen.
        true2_r = await ctx.send(point, true_p)
        false2_r = await ctx.send(point, point.original + false_p)
        if true2_r is None or false2_r is None:
            return []
        if not wider_then_same(baseline.norm_body, baseline.length, true2_r.text, false2_r.text):
            continue
        return [
            _hit(
                point,
                true_p,
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "LDAP injection via the '{param}' parameter (result set widened)",
                (
                    "Result sizes",
                    f"baseline {baseline.length} B, always-true {len(true_r.text)} B, "
                    f"always-false {len(false_r.text)} B",
                ),
            )
        ]
    return []


def _hit(
    point: InjectionPoint,
    payload: str,
    severity: Severity,
    confidence: Confidence,
    title: str,
    proof: tuple[str, str],
) -> InjectionHit:
    """
    Args:
        point (InjectionPoint): The point under test.
        payload (str): The payload that worked.
        severity (Severity): Finding severity.
        confidence (Confidence): Finding confidence.
        title (str): Title template with a ``{param}`` placeholder.
        proof (tuple[str, str]): The ``(label, content)`` evidence pair proving
            the hit.

    Returns:
        InjectionHit: The confirmed ``ldap`` hit.
    """
    return InjectionHit(
        kind="ldap",
        check_id=_CHECK_ID,
        method=point.method,
        url=point.base_url,
        param=point.param,
        severity=severity,
        confidence=confidence,
        title=title.format(param=point.param),
        payload=payload,
        evidence=(
            ("Injection point", f"{point.method} {point.base_url} — parameter '{point.param}'"),
            ("Payload", payload),
            proof,
        ),
    )
