"""
Open-redirect detector — spec 006 RF-11, RF-13.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

from webvigil.checks.injection.detect import DetectCtx, normalize_body, redirect
from webvigil.checks.injection.models import Baseline, InjectionPoint
from webvigil.http.client import Response

_POINT = InjectionPoint("GET", "https://example.com/go", "next", "/home", (("next", "/home"),))
_BASELINE = Baseline(200, "<p>home</p>", normalize_body("<p>home</p>"), 11, 1.0)


def _resp(
    *,
    status: int = 200,
    location: str | None = None,
    final_location: str | None = None,
    text: str = "<p>ok</p>",
) -> Response:
    headers = httpx.Headers({"content-type": "text/html"})
    if location is not None:
        headers["location"] = location
    return Response(
        url="https://example.com/go",
        requested_url="https://example.com/go",
        status_code=status,
        headers=headers,
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
        redirected_out_of_scope=final_location is not None,
        final_location=final_location,
    )


def _ctx(render: Callable[[str], Response]) -> DetectCtx:
    async def send(point: InjectionPoint, value: str, *, time_based: bool = False) -> Response:
        return render(value)

    return DetectCtx(send=send, delay_s=5, host="example.com")


async def test_final_location_to_the_sentinel_is_a_hit() -> None:
    hits = await redirect.detect(
        _POINT,
        _BASELINE,
        _ctx(lambda v: _resp(status=302, final_location="https://webvigil.invalid/")),
    )
    assert len(hits) == 1 and hits[0].kind == "redirect"
    assert hits[0].confidence.name == "HIGH"


async def test_location_header_to_the_sentinel_is_a_hit() -> None:
    hits = await redirect.detect(
        _POINT, _BASELINE, _ctx(lambda v: _resp(status=302, location="https://webvigil.invalid/x"))
    )
    assert len(hits) == 1


async def test_protocol_relative_and_backslash_forms_are_caught() -> None:
    def render(value: str) -> Response:
        # honour only the protocol-relative payload, echo the rest back on-site
        if value.startswith("//") or value.startswith("/\\") or "\\\\" in value:
            return _resp(status=302, final_location="https://webvigil.invalid/")
        return _resp(status=302, location="/home")

    hits = await redirect.detect(_POINT, _BASELINE, _ctx(render))
    assert len(hits) == 1


async def test_meta_refresh_and_js_body_are_medium() -> None:
    body = '<meta http-equiv="refresh" content="0;url=https://webvigil.invalid/">'
    hits = await redirect.detect(_POINT, _BASELINE, _ctx(lambda v: _resp(text=body)))
    assert hits and hits[0].confidence.name == "MEDIUM"

    js = '<script>location.href = "https://webvigil.invalid/"</script>'
    hits = await redirect.detect(_POINT, _BASELINE, _ctx(lambda v: _resp(text=js)))
    assert hits and hits[0].confidence.name == "MEDIUM"


async def test_same_host_redirect_is_not_a_hit() -> None:
    hits = await redirect.detect(
        _POINT, _BASELINE, _ctx(lambda v: _resp(status=302, location="https://example.com/home"))
    )
    assert hits == []
