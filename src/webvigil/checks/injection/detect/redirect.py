"""
Open-redirect detector — an off-site value is honoured in the redirect target (RF-11).

WebVigil inspects the ``Location`` header (and a ``<meta refresh>`` /
``location.href`` in the body); it never follows the redirect to the sentinel
host (RF-02) — the HTTP layer has already refused the off-scope hop and recorded
it in ``final_location``.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx
from webvigil.checks.injection.models import Baseline, InjectionHit, InjectionPoint
from webvigil.core.findings import Confidence, Severity
from webvigil.core.urls import resolve_url
from webvigil.http.client import Response

_CHECK_ID = "injection.redirect.open"
_SENTINEL = payloads.REDIRECT_SENTINEL
# Every repetition is bounded: the patterns read text the scanned site chose, and an open-ended
# run before the sentinel costs time proportional to the square of the body.
_META_RE = re.compile(r"http-equiv=[\"']?refresh[\"']?[^>]{0,500}" + re.escape(_SENTINEL), re.I)
_JS_RE = re.compile(
    r"location\s{0,20}(?:\.\s{0,20}(?:href|replace)\s{0,20})?[=(]\s{0,20}[\"'][^\"']{0,500}"
    + re.escape(_SENTINEL),
    re.I,
)


async def detect(point: InjectionPoint, baseline: Baseline, ctx: DetectCtx) -> list[InjectionHit]:
    """
    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response (unused — the sentinel host
            is unambiguous).
        ctx (DetectCtx): The budget-aware send context.

    Returns:
        list[InjectionHit]: A single ``redirect`` hit when the sentinel host
            reaches the ``Location`` (HIGH) or a ``<meta refresh>`` /
            ``location`` assignment (MEDIUM), else empty.
    """
    for template in payloads.REDIRECT_PAYLOADS:
        payload = payloads.fill_host(template, ctx.host)
        if payload is None:
            continue
        response = await ctx.send(point, payload)
        if response is None:
            break
        mechanism, confidence = _honoured(response)
        if mechanism is None:
            continue
        return [
            InjectionHit(
                kind="redirect",
                check_id=_CHECK_ID,
                method=point.method,
                url=point.base_url,
                param=point.param,
                severity=Severity.MEDIUM,
                confidence=confidence,
                title=f"Open redirect via the '{point.param}' parameter",
                payload=payload,
                evidence=(
                    (
                        "Injection point",
                        f"{point.method} {point.base_url} — parameter '{point.param}'",
                    ),
                    ("Payload", payload),
                    ("Redirect", mechanism),
                ),
            )
        ]
    return []


def _honoured(response: Response) -> tuple[str | None, Confidence]:
    """
    Args:
        response (Response): The response to the redirect payload.

    Returns:
        tuple[str | None, Confidence]: A description of how the sentinel was
            honoured and the confidence, or ``(None, LOW)`` when it was not.
    """
    if response.final_location and _host(response.final_location) == _SENTINEL:
        return f"Location -> {response.final_location}", Confidence.HIGH
    location = response.headers.get("location")
    resolved = resolve_url(response.url, location) if location else None
    if resolved is not None and _host(resolved) == _SENTINEL:
        return f"Location -> {location}", Confidence.HIGH
    if _META_RE.search(payloads.head(response.text)):
        return "meta refresh", Confidence.MEDIUM
    if _JS_RE.search(payloads.head(response.text)):
        return "JavaScript location assignment", Confidence.MEDIUM
    return None, Confidence.LOW


def _host(url: str) -> str:
    r"""
    Args:
        url (str): A possibly-malformed redirect target (backslashes,
            scheme-relative).

    Returns:
        str: Its lower-cased host, normalising ``\`` to ``/`` and a leading
            ``//`` to ``http://``; ``""`` when the target does not parse (an
            unbalanced IPv6 bracket), since it then names no host.
    """
    candidate = url.replace("\\", "/").strip()
    if candidate.startswith("//"):
        candidate = "http:" + candidate
    try:
        return (urlsplit(candidate).hostname or "").lower()
    except ValueError:
        return ""
