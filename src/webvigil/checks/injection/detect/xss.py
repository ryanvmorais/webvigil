"""Reflected-XSS detector — reflection + context analysis, no JS execution (RF-08, ADR-5).

A hit needs a context-breaking payload reflected in an HTML response with its
HTML-significant characters (`<`, `>`, `"`) intact — i.e. the app neither entity-encoded
nor percent-encoded nor stripped them.
"""

from __future__ import annotations

import secrets

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx
from webvigil.checks.injection.models import Baseline, InjectionHit, InjectionPoint
from webvigil.core.findings import Confidence, Severity

_CHECK_ID = "injection.xss.reflected"
_MAX_BREAKERS = 3


async def detect(point: InjectionPoint, baseline: Baseline, ctx: DetectCtx) -> list[InjectionHit]:
    token = "wv" + secrets.token_hex(payloads.XSS_TOKEN_BYTES)
    probe = payloads.XSS_PROBE.format(token=token[2:])
    response = await ctx.send(point, probe)
    if response is None or probe not in response.text:
        return []  # nothing reflects — no point trying to break out of context

    for template in payloads.XSS_BREAKERS[:_MAX_BREAKERS]:
        payload = template.format(token=token[2:])
        response = await ctx.send(point, payload)
        if response is None:
            break
        if not response.is_html or payload not in response.text:
            continue
        context = _context(response.text, payload)
        confidence = Confidence.MEDIUM if context == "script" else Confidence.HIGH
        return [
            InjectionHit(
                kind="xss",
                check_id=_CHECK_ID,
                method=point.method,
                url=point.base_url,
                param=point.param,
                severity=Severity.HIGH,
                confidence=confidence,
                title=f"Reflected XSS via the '{point.param}' parameter",
                payload=payload,
                evidence=(
                    (
                        "Injection point",
                        f"{point.method} {point.base_url} — parameter '{point.param}'",
                    ),
                    ("Payload", payload),
                    ("Reflection context", context),
                    ("Response snippet", _snippet(response.text, payload)),
                ),
            )
        ]
    return []


def _context(body: str, payload: str) -> str:
    before = body[: body.find(payload)].lower()
    if before.rfind("<script") > before.rfind("</script>"):
        return "script"
    if before.rfind("<") > before.rfind(">"):
        return "attribute"
    return "html body"


def _snippet(body: str, payload: str, *, span: int = 80) -> str:
    idx = body.find(payload)
    start = max(0, idx - span)
    end = min(len(body), idx + len(payload) + span)
    return ("…" if start else "") + body[start:end].strip() + ("…" if end < len(body) else "")
