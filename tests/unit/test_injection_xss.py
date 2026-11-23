"""
Reflected-XSS detector — spec 006 RF-08, RF-13.

Pure detector unit: ``_ctx`` wraps a ``render`` callable as the scanner's
``send``, so each test decides exactly what the "target" echoes back and no HTTP
is issued. ``_BASELINE`` is the pre-injection response the detector diffs
against.
"""

from __future__ import annotations

import html as html_mod
import re
from collections.abc import Callable

import httpx2
import pytest

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx, xss
from webvigil.checks.injection.models import Baseline, InjectionPoint
from webvigil.http.client import Response

_POINT = InjectionPoint("GET", "https://example.com/s", "q", "", (("q", ""),))
_BASELINE = Baseline(200, "<html>base</html>", "base", 17, 1.0)


def _resp(text: str, *, content_type: str = "text/html") -> Response:
    """
    Args:
        text (str): The response body.
        content_type (str): The ``Content-Type`` header. Defaults to ``text/html``.

    Returns:
        Response: A 200 response carrying ``text``.
    """
    return Response(
        url="https://example.com/s",
        requested_url="https://example.com/s",
        status_code=200,
        headers=httpx2.Headers({"content-type": content_type}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
    )


def _ctx(render: Callable[[str], Response | None], *, seen: list[str] | None = None) -> DetectCtx:
    """
    Args:
        render (Callable[[str], Response | None]): Maps an injected value to the response
            the target would return, or ``None`` to model a denied request.
        seen (list[str] | None): When given, every value sent is appended to it.

    Returns:
        DetectCtx: A detector context whose ``send`` calls ``render``.
    """

    async def send(
        point: InjectionPoint, value: str, *, time_based: bool = False
    ) -> Response | None:
        if seen is not None:
            seen.append(value)
        return render(value)

    return DetectCtx(send=send, delay_s=5, host="example.com")


async def test_verbatim_reflection_in_html_body_is_a_hit() -> None:
    """A value echoed verbatim into the HTML body is a HIGH-confidence hit."""
    hits = await xss.detect(
        _POINT, _BASELINE, _ctx(lambda v: _resp(f"<div>you searched {v}</div>"))
    )
    assert len(hits) == 1
    assert hits[0].kind == "xss" and hits[0].param == "q"
    assert hits[0].confidence.name == "HIGH"


async def test_reflection_inside_a_script_block_is_medium() -> None:
    """Reflection inside a ``<script>`` block is MEDIUM, with the context recorded."""
    hits = await xss.detect(
        _POINT, _BASELINE, _ctx(lambda v: _resp(f"<script>var q = {v};</script>"))
    )
    assert hits and hits[0].confidence.name == "MEDIUM"
    assert hits[0].evidence[2] == ("Reflection context", "script")


async def test_entity_encoded_reflection_is_not_a_hit() -> None:
    """An HTML-entity-encoded reflection is not exploitable, so not a hit."""
    hits = await xss.detect(
        _POINT, _BASELINE, _ctx(lambda v: _resp(f"<div>{html_mod.escape(v)}</div>"))
    )
    assert hits == []


async def test_percent_encoded_reflection_is_not_a_hit() -> None:
    """A percent-encoded reflection is likewise inert, so not a hit."""
    from urllib.parse import quote

    hits = await xss.detect(_POINT, _BASELINE, _ctx(lambda v: _resp(f"<div>{quote(v)}</div>")))
    assert hits == []


async def test_reflection_in_a_plain_text_response_is_not_a_hit() -> None:
    """Reflection only counts in an HTML response, never in ``text/plain``."""
    hits = await xss.detect(_POINT, _BASELINE, _ctx(lambda v: _resp(v, content_type="text/plain")))
    assert hits == []


async def test_no_reflection_short_circuits_after_the_probe() -> None:
    """When the plain probe is not reflected the detector stops after one request."""
    calls = 0

    def render(value: str) -> Response:
        nonlocal calls
        calls += 1
        return _resp("<div>static</div>")

    hits = await xss.detect(_POINT, _BASELINE, _ctx(render))
    assert hits == []
    assert calls == 1  # only the plain probe was sent


async def test_budget_denial_stops_the_detector() -> None:
    """When ``send`` returns ``None`` (budget denied) the detector yields nothing."""

    async def send(point: InjectionPoint, value: str, *, time_based: bool = False) -> None:
        return None

    hits = await xss.detect(_POINT, _BASELINE, DetectCtx(send=send, delay_s=5, host="example.com"))
    assert hits == []


def _fixed_token(monkeypatch: pytest.MonkeyPatch) -> tuple[str, list[str]]:
    """
    Args:
        monkeypatch (pytest.MonkeyPatch): Fixes the detector's random token.

    Returns:
        tuple[str, list[str]]: The probe and the breakers, in the order the detector sends them.
    """
    monkeypatch.setattr(xss.secrets, "token_hex", lambda n: "abc")
    return payloads.XSS_PROBE.format(token="abc"), [
        b.format(token="abc") for b in payloads.XSS_BREAKERS
    ]


async def test_a_denied_breaker_stops_the_detector(monkeypatch: pytest.MonkeyPatch) -> None:
    """A ``None`` after the probe ends the loop: nothing is sent after it."""
    probe, breakers = _fixed_token(monkeypatch)
    seen: list[str] = []
    hits = await xss.detect(
        _POINT, _BASELINE, _ctx(lambda v: _resp(v) if v == probe else None, seen=seen)
    )
    assert hits == []
    assert seen == [probe, breakers[0]]


async def test_only_the_first_three_breakers_are_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    """A page that strips markup reflects only the fourth breaker, which is never sent."""
    probe, breakers = _fixed_token(monkeypatch)
    seen: list[str] = []
    hits = await xss.detect(
        _POINT, _BASELINE, _ctx(lambda v: _resp(re.sub(r"[<>\"']", "", v)), seen=seen)
    )
    assert re.sub(r"[<>\"']", "", breakers[3]) == breakers[3]  # it would have come back whole
    assert hits == []
    assert seen == [probe, *breakers[:3]]


async def test_the_third_breaker_is_tried(monkeypatch: pytest.MonkeyPatch) -> None:
    """A page that mangles the first two breakers is caught by the third."""
    _, breakers = _fixed_token(monkeypatch)
    hits = await xss.detect(
        _POINT,
        _BASELINE,
        _ctx(lambda v: _resp("<div>" + v.replace("'", "").replace("svg", "") + "</div>")),
    )
    assert [hit.payload for hit in hits] == [breakers[2]]


async def test_reflection_inside_a_tag_is_the_attribute_context() -> None:
    """A value echoed into an attribute value lands inside an open tag."""
    hits = await xss.detect(
        _POINT, _BASELINE, _ctx(lambda v: _resp(f'<input name="q" value="{v}">'))
    )
    assert hits and dict(hits[0].evidence)["Reflection context"] == "attribute"
    assert hits[0].confidence.name == "HIGH"


def test_a_reflection_at_the_start_of_the_body_is_the_html_body_context() -> None:
    """With no tag before it at all, the payload is in the body, not in an attribute."""
    assert xss._context("PAYLOAD</div>", "PAYLOAD") == "html body"


def test_the_snippet_keeps_80_characters_on_each_side() -> None:
    """Past 80 characters either side the body is cut and marked; a body that fits is whole."""
    fits = "a" * 80 + "PAYLOAD" + "b" * 80
    assert xss._snippet(fits, "PAYLOAD") == fits
    assert xss._snippet("x" + fits + "y", "PAYLOAD") == "…" + fits + "…"
