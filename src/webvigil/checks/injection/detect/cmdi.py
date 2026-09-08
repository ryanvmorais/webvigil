"""
OS command-injection detector — prove shell execution from a side effect (spec 011, RF-02, RF-03).

Two stages, both drawing on the shared budget:

1. **echo** — append a shell-metacharacter break plus ``echo <marker>=$((a*b))``; a hit
   needs ``<marker>=<a*b>`` (the *evaluated* product, glued to a per-request marker) in the
   response and absent from the baseline. A reflected literal ``$((a*b))`` is not a hit
   (ADR-4).
2. **time** — ``sleep <d>`` / ``ping -n`` payloads, confirmed against a ``<d>=0`` control
   and a half-delay probe, exactly like :func:`~webvigil.checks.injection.detect.sqli.detect_time`.
   Runs only when ``ctx.time_based_cmdi`` is on.

Truly blind command injection — no output *and* no timing signal — needs a hosted OAST
collaborator and is not on the roadmap (``docs/notes/why-not-oast.md``); the time stage is
the in-band substitute, as ``sqli-time`` is for blind SQLi.
"""

from __future__ import annotations

import random
import secrets

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx
from webvigil.checks.injection.models import Baseline, InjectionHit, InjectionPoint
from webvigil.checks.injection.points import is_shell_param
from webvigil.core.findings import Confidence, Severity

_CHECK_ID = "injection.cmdi.os"

# A non-command-shaped point gets this subset, not the full CMDI_ECHO_POSIX (ADR-7).
_ECHO_CANARY: tuple[str, ...] = (
    ";echo {marker}=$(({a}*{b}))",
    "|echo {marker}=$(({a}*{b}))",
    "`echo {marker}=$(({a}*{b}))`",
)


async def detect(point: InjectionPoint, baseline: Baseline, ctx: DetectCtx) -> list[InjectionHit]:
    """
    Run the echo stage, then the time stage (if enabled), stopping at the first hit.

    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response; every proof must be absent
            from it.
        ctx (DetectCtx): The budget-aware send context; ``ctx.time_based_cmdi``
            gates the time stage, ``ctx.delay_s`` is the requested delay.

    Returns:
        list[InjectionHit]: A single ``cmdi`` hit (CRITICAL; HIGH confidence for
            the POSIX echo and the confirmed delay, MEDIUM for the Windows echo
            and a budget-truncated delay), or empty.
    """
    marker = "wv" + secrets.token_hex(payloads.CMDI_MARKER_BYTES)
    a, b = random.randint(11, 99), random.randint(11, 99)
    hit = await _echo(point, baseline, ctx, marker, a, b)
    # The time stage is the slow one and only makes sense for a shell-shaped parameter — a
    # `sleep` payload on a `name` / `template` sink just wastes the budget.
    if hit is None and ctx.time_based_cmdi and is_shell_param(point):
        hit = await _time(point, baseline, ctx)
    return [hit] if hit is not None else []


async def _echo(
    point: InjectionPoint, baseline: Baseline, ctx: DetectCtx, marker: str, a: int, b: int
) -> InjectionHit | None:
    """
    POSIX arithmetic-echo, then a lower-confidence Windows ``set /a`` variant.

    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response.
        ctx (DetectCtx): The budget-aware send context.
        marker (str): The per-request marker (``wv`` + token_hex).
        a (int): First operand.
        b (int): Second operand.

    Returns:
        InjectionHit | None: A CRITICAL ``cmdi`` hit, or ``None``.
    """
    needle = f"{marker}={a * b}"
    templates = payloads.CMDI_ECHO_POSIX if is_shell_param(point) else _ECHO_CANARY
    for template in templates:
        payload = point.original + template.format(marker=marker, a=a, b=b)
        response = await ctx.send(point, payload)
        if response is None:
            return None
        if needle in response.text and needle not in baseline.raw_body:
            return _echo_hit(point, payload, response.text, needle, Confidence.HIGH)

    for template in payloads.CMDI_ECHO_WINDOWS:
        payload = point.original + template.format(marker=marker, a=a, b=b)
        response = await ctx.send(point, payload)
        if response is None:
            return None
        if marker in baseline.raw_body:
            continue  # the marker was already echoed pre-injection — not a new signal
        start = response.text.find(marker)
        if start != -1 and str(a * b) in response.text[start : start + 200]:
            return _echo_hit(point, payload, response.text, marker, Confidence.MEDIUM)
    return None


async def _time(point: InjectionPoint, baseline: Baseline, ctx: DetectCtx) -> InjectionHit | None:
    """
    A payload that sleeps ``ctx.delay_s`` seconds must slow the response and scale.

    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response, for the timing floor.
        ctx (DetectCtx): The budget-aware send context.

    Returns:
        InjectionHit | None: A CRITICAL ``cmdi`` hit (HIGH confidence, MEDIUM
            when the confirmation request was budget-denied), or ``None``.
    """
    delay = ctx.delay_s
    threshold_ms = (delay - 1) * 1000
    for label, template in payloads.CMDI_TIME:
        control = await ctx.send(point, point.original + template.format(d=0, d1=1))
        if control is None:
            return None
        slow = await ctx.send(
            point, point.original + template.format(d=delay, d1=delay + 1), time_based=True
        )
        if slow is None:
            return None
        floor_ms = max(control.elapsed_ms, baseline.elapsed_ms)
        if slow.elapsed_ms - floor_ms < threshold_ms:
            continue

        half = max(1, delay // 2)
        confirm = await ctx.send(
            point, point.original + template.format(d=half, d1=half + 1), time_based=True
        )
        confidence = Confidence.HIGH
        if confirm is None:
            confidence = Confidence.MEDIUM
        elif not (half - 1) * 1000 <= confirm.elapsed_ms - floor_ms <= (half + 2) * 1000:
            continue

        payload = point.original + template.format(d=delay, d1=delay + 1)
        return InjectionHit(
            kind="cmdi",
            check_id=_CHECK_ID,
            method=point.method,
            url=point.base_url,
            param=point.param,
            severity=Severity.CRITICAL,
            confidence=confidence,
            title=(f"OS command injection (time-based, {label}) via the '{point.param}' parameter"),
            payload=payload,
            evidence=(
                _point_evidence(point),
                ("Payload", payload),
                (
                    "Timing",
                    f"control {control.elapsed_ms:.0f} ms, injected {slow.elapsed_ms:.0f} ms "
                    f"(delay requested: {delay} s)",
                ),
            ),
        )
    return None


def _echo_hit(
    point: InjectionPoint, payload: str, body: str, anchor: str, confidence: Confidence
) -> InjectionHit:
    """
    Args:
        point (InjectionPoint): The point under test.
        payload (str): The payload that worked.
        body (str): The response body.
        anchor (str): The substring to centre the evidence snippet on.
        confidence (Confidence): HIGH for the POSIX proof, MEDIUM for Windows.

    Returns:
        InjectionHit: A CRITICAL ``cmdi`` hit.
    """
    return InjectionHit(
        kind="cmdi",
        check_id=_CHECK_ID,
        method=point.method,
        url=point.base_url,
        param=point.param,
        severity=Severity.CRITICAL,
        confidence=confidence,
        title=f"OS command injection via the '{point.param}' parameter",
        payload=payload,
        evidence=(
            _point_evidence(point),
            ("Payload", payload),
            ("Command output", _snippet(body, body.find(anchor))),
        ),
    )


def _point_evidence(point: InjectionPoint) -> tuple[str, str]:
    """
    Args:
        point (InjectionPoint): The point under test.

    Returns:
        tuple[str, str]: The ``("Injection point", ...)`` evidence pair.
    """
    return ("Injection point", f"{point.method} {point.base_url} — parameter '{point.param}'")


def _snippet(body: str, index: int, *, limit: int = 200) -> str:
    """
    Args:
        body (str): The response body.
        index (int): Offset of the match (``-1`` → start of body).
        limit (int): Maximum characters to keep. Defaults to 200.

    Returns:
        str: The single line containing ``index``, trimmed to ``limit``.
    """
    index = max(index, 0)
    start = body.rfind("\n", 0, index) + 1
    end = body.find("\n", index)
    line = body[start : end if end != -1 else len(body)].strip()
    return line[:limit] + ("…" if len(line) > limit else "")
