"""Open-redirect detector — an off-site value is honoured in the redirect target (RF-11).

WebVigil inspects the ``Location`` header (and a ``<meta refresh>`` / ``location.href`` in
the body); it never follows the redirect to the sentinel host (RF-02) — the HTTP layer has
already refused the off-scope hop and recorded it in ``final_location``.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx
from webvigil.checks.injection.models import Baseline, InjectionHit, InjectionPoint
from webvigil.core.findings import Confidence, Severity
from webvigil.http.client import Response

_CHECK_ID = "injection.redirect.open"
_SENTINEL = payloads.REDIRECT_SENTINEL
_META_RE = re.compile(r"http-equiv=[\"']?refresh[\"']?[^>]*" + re.escape(_SENTINEL), re.I)
_JS_RE = re.compile(
    r"location\s*(?:\.\s*(?:href|replace)\s*)?[=(]\s*[\"'][^\"']*" + re.escape(_SENTINEL), re.I
)


async def detect(point: InjectionPoint, baseline: Baseline, ctx: DetectCtx) -> list[InjectionHit]:
    for template in payloads.REDIRECT_PAYLOADS:
        payload = template.replace("{host}", ctx.host)
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
    if response.final_location and _host(response.final_location) == _SENTINEL:
        return f"Location -> {response.final_location}", Confidence.HIGH
    location = response.headers.get("location")
    if location and _host(urljoin(response.url, location)) == _SENTINEL:
        return f"Location -> {location}", Confidence.HIGH
    if _META_RE.search(response.text):
        return "meta refresh", Confidence.MEDIUM
    if _JS_RE.search(response.text):
        return "JavaScript location assignment", Confidence.MEDIUM
    return None, Confidence.LOW


def _host(url: str) -> str:
    candidate = url.replace("\\", "/").strip()
    if candidate.startswith("//"):
        candidate = "http:" + candidate
    return (urlsplit(candidate).hostname or "").lower()
