"""
Server-side template injection detector — spec 011 RF-05, RF-06, RF-07, RF-14.

Pure detector unit: ``_ctx`` wraps a ``render`` callable as the scanner's
``send``. ``_jinja`` stands in for a name concatenated into a Jinja2 template
source — it evaluates ``{{a*b}}`` and ``{{7*'7'}}`` and raises the engine's
error string on the polyglot. ``_reflect`` echoes the payload unevaluated.
"""

from __future__ import annotations

import re
from collections.abc import Callable

import httpx
import pytest

from webvigil.checks.injection.detect import DetectCtx, normalize_body, ssti
from webvigil.checks.injection.models import Baseline, InjectionPoint
from webvigil.core.findings import Confidence, Severity
from webvigil.http.client import Response

_POINT = InjectionPoint("GET", "https://example.com/greet", "name", "friend", (("name", "x"),))
_PLAIN = InjectionPoint("GET", "https://example.com/x", "note", "hi", (("note", "hi"),))

_JINJA_ARITH = re.compile(r"(wv[0-9a-f]+)\{\{(\d+)\*(\d+)\}\}")
_JINJA_STR = re.compile(r"(wv[0-9a-f]+)\{\{7\*'7'\}\}")


def _resp(text: str, *, status: int = 200) -> Response:
    return Response(
        url="https://example.com/greet",
        requested_url="https://example.com/greet",
        status_code=status,
        headers=httpx.Headers({"content-type": "text/html"}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
    )


def _baseline(body: str = "<p>Hi friend</p>") -> Baseline:
    return Baseline(200, body, normalize_body(body), len(body), 1.0)


def _ctx(render: Callable[[str], Response | None]) -> DetectCtx:
    async def send(
        point: InjectionPoint, value: str, *, time_based: bool = False
    ) -> Response | None:
        return render(value)

    return DetectCtx(send=send, delay_s=5, host="example.com")


def _jinja(value: str, *, raise_on_polyglot: bool = True) -> Response:
    """A name concatenated into ``jinja2.Template("<p>Hi " + name + "</p>")``."""
    if "${{" in value and raise_on_polyglot:  # the polyglot
        return _resp("jinja2.exceptions.TemplateSyntaxError: unexpected char", status=500)
    arith = _JINJA_ARITH.search(value)
    if arith:
        product = int(arith.group(2)) * int(arith.group(3))
        return _resp(f"<p>Hi {arith.group(1)}{product}</p>")
    string = _JINJA_STR.search(value)
    if string:
        return _resp(f"<p>Hi {string.group(1)}7777777</p>")
    return _resp(f"<p>Hi {value}</p>")


def _reflect(value: str) -> Response:
    """The app that renders the value as data — the expression never evaluates."""
    return _resp(f"<p>Hi {value}</p>")


async def test_jinja_arithmetic_is_a_high_hit_with_engine_named() -> None:
    """``{{a*b}}`` returning the product, plus ``{{7*'7'}}`` → 7777777, names Jinja2."""
    hits = await ssti.detect(_POINT, _baseline(), _ctx(_jinja))
    assert len(hits) == 1
    hit = hits[0]
    assert hit.kind == "ssti"
    assert hit.check_id == "injection.ssti"
    assert hit.severity is Severity.HIGH
    assert hit.confidence is Confidence.HIGH
    assert "template injection" in hit.title.lower()
    assert "Jinja2" in hit.title


async def test_engine_named_from_the_polyglot_error_alone() -> None:
    """A Twig error on the polyglot names the engine even before the string probe."""

    def render(value: str) -> Response:
        if "${{" in value:
            return _resp("Twig\\Error\\SyntaxError: Unexpected token", status=500)
        arith = _JINJA_ARITH.search(value)
        if arith:
            return _resp(f"out {arith.group(1)}{int(arith.group(2)) * int(arith.group(3))}")
        return _resp("out")

    hits = await ssti.detect(_POINT, _baseline(), _ctx(render))
    assert hits and "Twig" in hits[0].title


async def test_arithmetic_fires_without_any_stage_one_error() -> None:
    """Stage 2 does not depend on stage 1 — an engine that does not error still gets caught."""
    hits = await ssti.detect(
        _POINT, _baseline(), _ctx(lambda v: _jinja(v, raise_on_polyglot=False))
    )
    assert len(hits) == 1
    assert hits[0].kind == "ssti"


async def test_reflected_literal_is_not_a_hit() -> None:
    """``{{a*b}}`` echoed back verbatim, unevaluated, is not a hit."""
    hits = await ssti.detect(_POINT, _baseline(), _ctx(_reflect))
    assert hits == []


async def test_product_without_the_marker_is_not_a_hit() -> None:
    """The product appearing on its own, not glued to the marker, is not a hit."""

    def render(value: str) -> Response:
        if _JINJA_ARITH.search(value):
            return _resp("<p>total: 221 items</p>")  # 221 present, marker absent
        return _resp("<p>Hi</p>")

    hits = await ssti.detect(_POINT, _baseline(), _ctx(render))
    assert hits == []


async def test_needle_already_in_the_baseline_is_suppressed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A needle already in the baseline body is not a new finding."""
    monkeypatch.setattr(
        "webvigil.checks.injection.detect.ssti.secrets.token_hex", lambda n: "abcdef"
    )
    monkeypatch.setattr("webvigil.checks.injection.detect.ssti.random.randint", lambda lo, hi: 20)
    needle = "wvabcdef400"  # 20 * 20
    hits = await ssti.detect(
        _POINT, _baseline(f"<p>token {needle}</p>"), _ctx(lambda v: _resp(f"<p>{needle}</p>"))
    )
    assert hits == []


async def test_detector_stops_when_send_returns_none() -> None:
    """A ``None`` from ``send`` on the polyglot stops the detector immediately."""
    hits = await ssti.detect(_POINT, _baseline(), _ctx(lambda v: None))
    assert hits == []
