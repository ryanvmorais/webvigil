"""
Server-side template injection detector — polyglot probe, then arithmetic (spec 011, RF-05, RF-06).

Stage 1 sends the PortSwigger SSTI polyglot and reads the response for a template-engine
parse error (which names the engine). Stage 2 sends per-engine arithmetic payloads with a
per-request marker glued to the expression; a hit needs ``<marker><a*b>`` (the *evaluated*
product) in the response and absent from the baseline (ADR-4) — a reflected literal
``{{a*b}}`` is not a hit. An optional third request (``{{7*'7'}}``) identifies the engine
when the error did not.
"""

from __future__ import annotations

import random
import secrets

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx
from webvigil.checks.injection.models import Baseline, InjectionHit, InjectionPoint
from webvigil.checks.injection.points import is_commandlike
from webvigil.core.findings import Confidence, Severity

_CHECK_ID = "injection.ssti"

# A non-command/template-shaped point only gets the first few arithmetic payloads (ADR-7).
_CANARY_LIMIT = 4


async def detect(point: InjectionPoint, baseline: Baseline, ctx: DetectCtx) -> list[InjectionHit]:
    """
    Probe with the polyglot, then confirm with an arithmetic expression.

    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response; the proof must be absent from
            it.
        ctx (DetectCtx): The budget-aware send context.

    Returns:
        list[InjectionHit]: A single ``ssti`` hit (HIGH, confidence HIGH) naming
            the engine when known, or empty.
    """
    probe = await ctx.send(point, point.original + payloads.SSTI_POLYGLOT)
    if probe is None:
        return []
    engine = _engine_from_error(probe.text, baseline.raw_body)

    marker = "wv" + secrets.token_hex(payloads.SSTI_MARKER_BYTES)
    a, b = random.randint(11, 99), random.randint(11, 99)
    needle = f"{marker}{a * b}"
    candidates = payloads.arith_payloads(marker, a, b)
    if engine is not None:
        candidates = _engine_first(candidates, engine)
    if not is_commandlike(point):
        candidates = candidates[:_CANARY_LIMIT]

    for _hint, expr in candidates:
        response = await ctx.send(point, point.original + expr)
        if response is None:
            break
        if needle in response.text and needle not in baseline.raw_body:
            engine = engine or await _identify_engine(point, ctx, marker)
            return [_hit(point, engine, point.original + expr, needle, a, b)]
    return []


def _engine_from_error(text: str, baseline_text: str) -> str | None:
    """
    Args:
        text (str): The polyglot response body.
        baseline_text (str): The baseline body; a signature also present here is
            ignored.

    Returns:
        str | None: The first engine whose error signature is in ``text`` and not
            in the baseline, or ``None``.
    """
    for name, pattern in payloads.SSTI_ERROR_SIGNATURES:
        if pattern.search(text) and not pattern.search(baseline_text):
            return name
    return None


def _engine_first(
    candidates: tuple[tuple[str, str], ...], engine: str
) -> tuple[tuple[str, str], ...]:
    """
    Args:
        candidates (tuple[tuple[str, str], ...]): The ``(hint, payload)`` pairs.
        engine (str): The engine named by the stage-1 error.

    Returns:
        tuple[tuple[str, str], ...]: The same pairs, those whose hint mentions
            the engine moved to the front.
    """
    key = engine.split("/", 1)[0]
    matched = tuple(pair for pair in candidates if key in pair[0])
    rest = tuple(pair for pair in candidates if pair not in matched)
    return matched + rest


async def _identify_engine(point: InjectionPoint, ctx: DetectCtx, marker: str) -> str | None:
    """
    Args:
        point (InjectionPoint): The point under test.
        ctx (DetectCtx): The budget-aware send context.
        marker (str): The per-request marker.

    Returns:
        str | None: ``"Jinja2/Nunjucks"`` when ``{{7*'7'}}`` rendered
            ``7777777``, ``"Twig"`` when it rendered ``49``, else ``None`` (also
            ``None`` when the request was budget-denied).
    """
    response = await ctx.send(point, point.original + (payloads.SSTI_ENGINE_PROBE % marker))
    if response is None:
        return None
    if f"{marker}7777777" in response.text:
        return "Jinja2/Nunjucks"
    if f"{marker}49" in response.text:
        return "Twig"
    return None


def _hit(
    point: InjectionPoint, engine: str | None, payload: str, needle: str, a: int, b: int
) -> InjectionHit:
    """
    Args:
        point (InjectionPoint): The point under test.
        engine (str | None): The identified engine, or ``None``.
        payload (str): The payload that worked.
        needle (str): The ``<marker><product>`` string found in the response.
        a (int): First operand.
        b (int): Second operand.

    Returns:
        InjectionHit: A HIGH ``ssti`` hit.
    """
    return InjectionHit(
        kind="ssti",
        check_id=_CHECK_ID,
        method=point.method,
        url=point.base_url,
        param=point.param,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title=(
            f"Server-side template injection ({engine or 'engine unknown'}) "
            f"via the '{point.param}' parameter"
        ),
        payload=payload,
        evidence=(
            ("Injection point", f"{point.method} {point.base_url} — parameter '{point.param}'"),
            ("Payload", payload),
            ("Evaluated expression", f"{needle}  (= {a} * {b})"),
        ),
    )
