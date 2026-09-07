"""In-band SSRF detector — prove a server-side fetch from the target's own response (spec 009).

For an injection point the detector places URL payloads in the parameter and reads the
response for one of four proofs, each required *absent from the point's baseline*:

1. a cloud instance-metadata marker      -> ``ssrf-metadata``  (CRITICAL)
2. a ``file://`` read signature           -> ``ssrf-internal``  (HIGH)
3. a recognizable internal-service reply  -> ``ssrf-internal``  (HIGH)
4. an SSRF-shaped connection error that echoes the injected URL, or a ``502/504`` the
   baseline never returned, also echoing the URL -> ``ssrf-internal`` (HIGH / MEDIUM conf.)

Blind SSRF — a server-side request with no in-band signal at all — is out of scope; it
needs the deferred opt-in OAST collaborator. Every payload is a *value* sent to the target;
WebVigil only ever connects to the target host.
"""

from __future__ import annotations

import re

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx
from webvigil.checks.injection.models import Baseline, InjectionHit, InjectionPoint
from webvigil.checks.injection.points import is_urllike
from webvigil.core.findings import Confidence, Severity
from webvigil.http.client import Response

_METADATA_ID = "injection.ssrf.metadata"
_INTERNAL_ID = "injection.ssrf.internal"
_GATEWAY_STATUS = frozenset({502, 503, 504})

# A point with a URL-shaped name/value gets the full payload set; anything else gets a short
# canary (one per category) so an obvious sink with an unhelpful name is still caught
# without spending the point's budget on 26 requests.
_CANARY = (payloads.SSRF_METADATA[:2], payloads.SSRF_FILE[:1], payloads.SSRF_INTERNAL[:2])


async def detect(point: InjectionPoint, baseline: Baseline, ctx: DetectCtx) -> list[InjectionHit]:
    groups = (
        (payloads.SSRF_METADATA, payloads.SSRF_FILE, payloads.SSRF_INTERNAL)
        if is_urllike(point)
        else _CANARY
    )
    for group in groups:
        for template in group:
            payload = template.replace("{host}", ctx.host)
            response = await ctx.send(point, payload)
            if response is None:
                return []  # budget reached — stop, like every spec-006 detector
            hit = (
                _metadata_hit(point, baseline, payload, response)
                or _file_hit(point, baseline, payload, response)
                or _internal_hit(point, baseline, payload, response)
                or _error_hit(point, baseline, payload, response)
            )
            if hit is not None:
                return [hit]  # one hit per point is enough (as traversal / redirect)
    return []


def _metadata_hit(
    point: InjectionPoint, baseline: Baseline, payload: str, response: Response
) -> InjectionHit | None:
    for provider, pattern in payloads.SSRF_METADATA_SIGNATURES:
        match = pattern.search(response.text)
        if match and not pattern.search(baseline.raw_body):
            return InjectionHit(
                kind="ssrf-metadata",
                check_id=_METADATA_ID,
                method=point.method,
                url=point.base_url,
                param=point.param,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                title=(
                    f"SSRF to the {provider} instance metadata service via "
                    f"the '{point.param}' parameter"
                ),
                payload=payload,
                evidence=(
                    _point_evidence(point),
                    ("Payload", payload),
                    (f"{provider} metadata marker", _snippet(response.text, match.start())),
                ),
            )
    return None


def _file_hit(
    point: InjectionPoint, baseline: Baseline, payload: str, response: Response
) -> InjectionHit | None:
    if not payload.lower().startswith("file:"):
        return None
    for pattern in payloads.TRAVERSAL_SIGNATURES:
        match = pattern.search(response.text)
        if match and not pattern.search(baseline.raw_body):
            return InjectionHit(
                kind="ssrf-internal",
                check_id=_INTERNAL_ID,
                method=point.method,
                url=point.base_url,
                param=point.param,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title=f"SSRF local file read (file://) via the '{point.param}' parameter",
                payload=payload,
                evidence=(
                    _point_evidence(point),
                    ("Payload", payload),
                    ("Leaked file content", _snippet(response.text, match.start())),
                ),
            )
    return None


def _internal_hit(
    point: InjectionPoint, baseline: Baseline, payload: str, response: Response
) -> InjectionHit | None:
    for service, pattern in payloads.SSRF_INTERNAL_SIGNATURES:
        match = pattern.search(response.text)
        if match and not pattern.search(baseline.raw_body):
            return InjectionHit(
                kind="ssrf-internal",
                check_id=_INTERNAL_ID,
                method=point.method,
                url=point.base_url,
                param=point.param,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title=(
                    f"SSRF to an internal service ({service}) via the '{point.param}' parameter"
                ),
                payload=payload,
                evidence=(
                    _point_evidence(point),
                    ("Payload", payload),
                    (f"{service} response", _snippet(response.text, match.start())),
                ),
            )
    return None


def _error_hit(
    point: InjectionPoint, baseline: Baseline, payload: str, response: Response
) -> InjectionHit | None:
    authority = _authority(payload)
    if not authority or authority not in response.text:
        return None  # the injected URL must be echoed back (ADR-4)
    error = _first_match(payloads.SSRF_ERROR_SIGNATURES, response.text, baseline.raw_body)
    gateway = response.status_code in _GATEWAY_STATUS and response.status_code != baseline.status
    if error is None and not gateway:
        return None
    proof = error or (
        f"HTTP {response.status_code} (gateway error) with the injected URL echoed back"
    )
    return InjectionHit(
        kind="ssrf-internal",
        check_id=_INTERNAL_ID,
        method=point.method,
        url=point.base_url,
        param=point.param,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        title=f"SSRF — the '{point.param}' parameter is fetched server-side",
        payload=payload,
        evidence=(
            _point_evidence(point),
            ("Payload", payload),
            ("Server-side fetch", proof),
        ),
    )


def _point_evidence(point: InjectionPoint) -> tuple[str, str]:
    return ("Injection point", f"{point.method} {point.base_url} — parameter '{point.param}'")


def _authority(payload: str) -> str:
    """The host[:port] between ``://`` and the next ``/``, minus any ``user@`` prefix."""
    if "://" not in payload:
        return ""
    rest = payload.split("://", 1)[1]
    authority = rest.split("/", 1)[0].split("#", 1)[0].split("?", 1)[0]
    return authority.rsplit("@", 1)[-1]


def _first_match(
    patterns: tuple[re.Pattern[str], ...], text: str, baseline_text: str
) -> str | None:
    for pattern in patterns:
        match = pattern.search(text)
        if match and not pattern.search(baseline_text):
            return _snippet(text, match.start())
    return None


def _snippet(body: str, index: int, *, limit: int = 200) -> str:
    start = body.rfind("\n", 0, index) + 1
    end = body.find("\n", index)
    line = body[start : end if end != -1 else len(body)].strip()
    return line[:limit] + ("…" if len(line) > limit else "")
