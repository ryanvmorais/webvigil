"""
Open-redirect detector — spec 006 RF-11, RF-13.

Pure detector unit: ``_ctx`` wraps a ``render`` callable as the scanner's
``send``, so each test decides how the target responds to a payload (a
``Location`` header, an out-of-scope ``final_location``, a meta-refresh body)
and no HTTP is issued. The detector proves a redirect only when it lands on the
``webvigil.invalid`` sentinel host.
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
    """
    Args:
        status (int): The response status code.
        location (str | None): A ``Location`` header value, if any.
        final_location (str | None): The post-redirect URL when the chain left
            scope; also flips ``redirected_out_of_scope``.
        text (str): The response body.

    Returns:
        Response: The assembled response.
    """
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
    """
    Args:
        render (Callable[[str], Response]): Maps an injected value to the response
            the target would return.

    Returns:
        DetectCtx: A detector context whose ``send`` calls ``render``.
    """

    async def send(point: InjectionPoint, value: str, *, time_based: bool = False) -> Response:
        return render(value)

    return DetectCtx(send=send, delay_s=5, host="example.com")


async def test_final_location_to_the_sentinel_is_a_hit() -> None:
    """A redirect chain that ends on the sentinel host is a HIGH-confidence hit."""
    hits = await redirect.detect(
        _POINT,
        _BASELINE,
        _ctx(lambda v: _resp(status=302, final_location="https://webvigil.invalid/")),
    )
    assert len(hits) == 1 and hits[0].kind == "redirect"
    assert hits[0].confidence.name == "HIGH"


async def test_location_header_to_the_sentinel_is_a_hit() -> None:
    """A single ``Location`` header pointing at the sentinel is enough."""
    hits = await redirect.detect(
        _POINT, _BASELINE, _ctx(lambda v: _resp(status=302, location="https://webvigil.invalid/x"))
    )
    assert len(hits) == 1


async def test_protocol_relative_and_backslash_forms_are_caught() -> None:
    """The ``//host`` and backslash redirect-bypass payloads are exercised and caught."""

    def render(value: str) -> Response:
        # honour only the protocol-relative payload, echo the rest back on-site
        if value.startswith("//") or value.startswith("/\\") or "\\\\" in value:
            return _resp(status=302, final_location="https://webvigil.invalid/")
        return _resp(status=302, location="/home")

    hits = await redirect.detect(_POINT, _BASELINE, _ctx(render))
    assert len(hits) == 1


async def test_meta_refresh_and_js_body_are_medium() -> None:
    """A meta-refresh or JS ``location.href`` to the sentinel is a MEDIUM hit."""
    body = '<meta http-equiv="refresh" content="0;url=https://webvigil.invalid/">'
    hits = await redirect.detect(_POINT, _BASELINE, _ctx(lambda v: _resp(text=body)))
    assert hits and hits[0].confidence.name == "MEDIUM"

    js = '<script>location.href = "https://webvigil.invalid/"</script>'
    hits = await redirect.detect(_POINT, _BASELINE, _ctx(lambda v: _resp(text=js)))
    assert hits and hits[0].confidence.name == "MEDIUM"


async def test_same_host_redirect_is_not_a_hit() -> None:
    """A redirect that stays on the target host is not an open redirect."""
    hits = await redirect.detect(
        _POINT, _BASELINE, _ctx(lambda v: _resp(status=302, location="https://example.com/home"))
    )
    assert hits == []
