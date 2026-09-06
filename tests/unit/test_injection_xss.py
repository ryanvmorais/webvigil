"""Reflected-XSS detector — spec 006 RF-08, RF-13."""

from __future__ import annotations

import html as html_mod
from collections.abc import Callable

import httpx

from webvigil.checks.injection.detect import DetectCtx, xss
from webvigil.checks.injection.models import Baseline, InjectionPoint
from webvigil.http.client import Response

_POINT = InjectionPoint("GET", "https://example.com/s", "q", "", (("q", ""),))
_BASELINE = Baseline(200, "<html>base</html>", "base", 17, 1.0)


def _resp(text: str, *, content_type: str = "text/html") -> Response:
    return Response(
        url="https://example.com/s",
        requested_url="https://example.com/s",
        status_code=200,
        headers=httpx.Headers({"content-type": content_type}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
    )


def _ctx(render: Callable[[str], Response]) -> DetectCtx:
    async def send(point: InjectionPoint, value: str, *, time_based: bool = False) -> Response:
        return render(value)

    return DetectCtx(send=send, delay_s=5, host="example.com")


async def test_verbatim_reflection_in_html_body_is_a_hit() -> None:
    hits = await xss.detect(
        _POINT, _BASELINE, _ctx(lambda v: _resp(f"<div>you searched {v}</div>"))
    )
    assert len(hits) == 1
    assert hits[0].kind == "xss" and hits[0].param == "q"
    assert hits[0].confidence.name == "HIGH"


async def test_reflection_inside_a_script_block_is_medium() -> None:
    hits = await xss.detect(
        _POINT, _BASELINE, _ctx(lambda v: _resp(f"<script>var q = {v};</script>"))
    )
    assert hits and hits[0].confidence.name == "MEDIUM"
    assert hits[0].evidence[2] == ("Reflection context", "script")


async def test_entity_encoded_reflection_is_not_a_hit() -> None:
    hits = await xss.detect(
        _POINT, _BASELINE, _ctx(lambda v: _resp(f"<div>{html_mod.escape(v)}</div>"))
    )
    assert hits == []


async def test_percent_encoded_reflection_is_not_a_hit() -> None:
    from urllib.parse import quote

    hits = await xss.detect(_POINT, _BASELINE, _ctx(lambda v: _resp(f"<div>{quote(v)}</div>")))
    assert hits == []


async def test_reflection_in_a_plain_text_response_is_not_a_hit() -> None:
    hits = await xss.detect(_POINT, _BASELINE, _ctx(lambda v: _resp(v, content_type="text/plain")))
    assert hits == []


async def test_no_reflection_short_circuits_after_the_probe() -> None:
    calls = 0

    def render(value: str) -> Response:
        nonlocal calls
        calls += 1
        return _resp("<div>static</div>")

    hits = await xss.detect(_POINT, _BASELINE, _ctx(render))
    assert hits == []
    assert calls == 1  # only the plain probe was sent


async def test_budget_denial_stops_the_detector() -> None:
    async def send(point: InjectionPoint, value: str, *, time_based: bool = False) -> None:
        return None

    hits = await xss.detect(_POINT, _BASELINE, DetectCtx(send=send, delay_s=5, host="example.com"))
    assert hits == []
