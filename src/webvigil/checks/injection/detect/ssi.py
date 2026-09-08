"""
Server-Side Includes / ESI-injection detector — a directive the server evaluates (spec 014).

The payload is reflected into a page an SSI / ESI processor then evaluates. Two
signals:

* an **echo probe** injects ``<!--#echo var="DATE_LOCAL"-->`` / ``<!--#printenv-->``
  / ``<esi:vars>$(HTTP_HOST)</esi:vars>``; a hit needs the *evaluated* output (a
  rendered date, an environment dump, the host) in the response and absent from
  the baseline. The directive reflected **verbatim** is not a hit (ADR-8);
* a **marker probe** names an undefined variable; a hit needs the SSI processor's
  configured error string, absent from the baseline.

``<!--#exec-->`` and ``<!--#include-->`` are never sent — command execution and
file inclusion are the ``cmdi`` / ``traversal`` detectors' territory (RF-10).
"""

from __future__ import annotations

import secrets

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx
from webvigil.checks.injection.models import Baseline, InjectionHit, InjectionPoint
from webvigil.core.findings import Confidence, Severity

_CHECK_ID = "injection.ssi"


async def detect(point: InjectionPoint, baseline: Baseline, ctx: DetectCtx) -> list[InjectionHit]:
    """
    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response; a signature must be absent
            from it.
        ctx (DetectCtx): The budget-aware send context.

    Returns:
        list[InjectionHit]: A single ``ssi`` hit — HIGH for evaluated output,
            MEDIUM for the SSI error string — else empty.
    """
    for directive in payloads.SSI_ECHO:
        response = await ctx.send(point, point.original + directive)
        if response is None:
            return []
        if directive in response.text:
            continue  # reflected verbatim, not evaluated -> not an SSI hit
        for pattern in payloads.SSI_EVAL_SIGNATURES:
            match = pattern.search(response.text)
            if match and not pattern.search(baseline.raw_body):
                return [
                    _hit(
                        point,
                        point.original + directive,
                        Severity.HIGH,
                        Confidence.HIGH,
                        "SSI/ESI injection via the '{param}' parameter (directive evaluated)",
                        ("Evaluated output", match.group(0)),
                    )
                ]

    token = secrets.token_hex(payloads.SSI_MARKER_BYTES)
    marker = payloads.SSI_MARKER.format(token=token)
    response = await ctx.send(point, point.original + marker)
    if response is None:
        return []
    err = payloads.SSI_ERROR_SIGNATURE.search(response.text)
    if err and not payloads.SSI_ERROR_SIGNATURE.search(baseline.raw_body):
        return [
            _hit(
                point,
                point.original + marker,
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "SSI enabled via the '{param}' parameter (undefined-variable error)",
                ("SSI error", err.group(0)),
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
        InjectionHit: The confirmed ``ssi`` hit.
    """
    return InjectionHit(
        kind="ssi",
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
