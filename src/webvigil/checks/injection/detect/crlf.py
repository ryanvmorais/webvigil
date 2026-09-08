"""
CRLF-injection / HTTP-response-splitting detector (spec 012, RF-01, ADR-5).

For an injection point the detector appends ``%0d%0a``-prefixed payloads to the
value and checks whether the *response* carries something the baseline did not:

1. a marker header (``X-WvInjected: <token>``) that ``httpx`` parsed back;
2. a ``Set-Cookie`` split (``wv<token>=1``);
3. a full response-body split (the whole body is the marker).

A payload merely reflected in the response *body text* is **not** a hit — that
is reflected-XSS / open-redirect territory. Modern servers strip CR LF from
header values, so a real target may be a false negative even when vulnerable;
the fixture simulates the permissive-server case.
"""

from __future__ import annotations

import secrets

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx
from webvigil.checks.injection.models import Baseline, InjectionHit, InjectionPoint
from webvigil.checks.injection.points import is_headerlike
from webvigil.core.findings import Confidence, Severity

_CHECK_ID = "injection.crlf"
_CANARY = 2


async def detect(point: InjectionPoint, baseline: Baseline, ctx: DetectCtx) -> list[InjectionHit]:
    """
    Send CRLF payloads and check the response for an injected header / cookie / body split.

    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response; every proof must be absent
            from it.
        ctx (DetectCtx): The budget-aware send context.

    Returns:
        list[InjectionHit]: A single HIGH ``crlf`` hit, or empty.
    """
    token = secrets.token_hex(payloads.CRLF_TOKEN_BYTES)
    header = payloads.CRLF_HEADER
    body_marker = payloads.CRLF_BODY_MARKER.format(token=token)
    templates = payloads.CRLF_PAYLOADS if is_headerlike(point) else payloads.CRLF_PAYLOADS[:_CANARY]

    # A benign baseline of our own: learn what the endpoint sets on an ordinary request so
    # "the target always emits X-WvInjected" is never a false positive.
    base = await ctx.send(point, point.original)
    if base is None:
        return []
    base_has_header = header.lower() in base.headers
    base_cookie = base.headers.get("set-cookie", "")

    for template in templates:
        payload = point.original + template.format(header=header, token=token, body=body_marker)
        response = await ctx.send(point, payload)
        if response is None:
            return []

        if response.headers.get(header.lower()) == token and not base_has_header:
            return [_hit(point, payload, "response header", f"{header}: {token}")]

        cookie = response.headers.get("set-cookie", "")
        if f"wv{token}=1" in cookie and f"wv{token}=1" not in base_cookie:
            return [_hit(point, payload, "Set-Cookie split", cookie[:200])]

        if response.text.strip() == body_marker and body_marker not in baseline.raw_body:
            return [_hit(point, payload, "response body split", response.text[:200])]
    return []


def _hit(point: InjectionPoint, payload: str, mechanism: str, proof: str) -> InjectionHit:
    """
    Args:
        point (InjectionPoint): The point under test.
        payload (str): The payload that worked.
        mechanism (str): ``"response header"`` / ``"Set-Cookie split"`` /
            ``"response body split"``.
        proof (str): The injected header / cookie / body snippet.

    Returns:
        InjectionHit: A HIGH ``crlf`` hit.
    """
    return InjectionHit(
        kind="crlf",
        check_id=_CHECK_ID,
        method=point.method,
        url=point.base_url,
        param=point.param,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title=f"CRLF injection / HTTP response splitting via the '{point.param}' parameter",
        payload=payload,
        evidence=(
            ("Injection point", f"{point.method} {point.base_url} — parameter '{point.param}'"),
            ("Payload", payload),
            (f"Injected ({mechanism})", proof),
        ),
    )
