"""
XPath / XQuery-injection detector — a parser error, or a boolean split (spec 014, RF-09).

The payload reaches an XPath expression the application builds over an XML store.
Two signals, both differential:

* an **error probe** appends an expression-breaking character; a hit needs an
  XPath/XQuery parser error in the response, absent from the baseline;
* a **boolean probe** sends a tautology (``' or '1'='1``) and a contradiction
  (``' and '1'='2``); a hit needs the classic two-sided split
  (:func:`~webvigil.checks.injection.detect._diff.two_sided_split`) to reproduce.

WebVigil parses no XML / XPath itself — it sends the payload and reads the response.
"""

from __future__ import annotations

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx
from webvigil.checks.injection.detect._diff import two_sided_split
from webvigil.checks.injection.models import Baseline, InjectionHit, InjectionPoint
from webvigil.core.findings import Confidence, Severity

_CHECK_ID = "injection.xpath"


async def detect(point: InjectionPoint, baseline: Baseline, ctx: DetectCtx) -> list[InjectionHit]:
    """
    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response; a signature must be absent
            from it.
        ctx (DetectCtx): The budget-aware send context.

    Returns:
        list[InjectionHit]: A single ``xpath`` hit — HIGH for a parser error,
            MEDIUM for a reproduced boolean split — else empty.
    """
    for probe in payloads.XPATH_ERROR:
        response = await ctx.send(point, point.original + probe)
        if response is None:
            return []
        for pattern in payloads.XPATH_ERROR_SIGNATURES:
            match = pattern.search(response.text)
            if match and not pattern.search(baseline.raw_body):
                return [
                    _hit(
                        point,
                        point.original + probe,
                        Severity.HIGH,
                        Confidence.HIGH,
                        "XPath injection via the '{param}' parameter (expression error)",
                        ("XPath error", match.group(0)),
                    )
                ]

    for true_p, false_p in payloads.XPATH_BOOLEAN_PAIRS:
        true_r = await ctx.send(point, point.original + true_p)
        false_r = await ctx.send(point, point.original + false_p)
        if true_r is None or false_r is None:
            return []
        if not two_sided_split(baseline.norm_body, true_r.text, false_r.text):
            continue
        true2_r = await ctx.send(point, point.original + true_p)
        false2_r = await ctx.send(point, point.original + false_p)
        if true2_r is None or false2_r is None:
            return []
        if not two_sided_split(baseline.norm_body, true2_r.text, false2_r.text):
            continue
        return [
            _hit(
                point,
                point.original + true_p,
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "XPath injection via the '{param}' parameter (boolean-based blind)",
                (
                    "TRUE / FALSE payloads",
                    f"{point.original + true_p!r} vs {point.original + false_p!r}",
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
        proof (tuple[str, str]): The ``(label, content)`` evidence pair.

    Returns:
        InjectionHit: The confirmed ``xpath`` hit.
    """
    return InjectionHit(
        kind="xpath",
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
