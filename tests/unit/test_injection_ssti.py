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

import httpx2
import pytest

from webvigil.checks.injection import payloads
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
        headers=httpx2.Headers({"content-type": "text/html"}),
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


# ---------------------------------------------------------------------------
# Which forms are sent, in which order, and how the engine is named
# ---------------------------------------------------------------------------


def _fixed(monkeypatch: pytest.MonkeyPatch) -> tuple[tuple[str, str], ...]:
    """
    Args:
        monkeypatch (pytest.MonkeyPatch): Fixes the detector's marker and operands.

    Returns:
        tuple[tuple[str, str], ...]: The ``(hint, expression)`` forms, in catalog order.
    """
    monkeypatch.setattr("webvigil.checks.injection.detect.ssti.secrets.token_hex", lambda n: "abc")
    monkeypatch.setattr("webvigil.checks.injection.detect.ssti.random.randint", lambda lo, hi: 20)
    return payloads.arith_payloads("wvabc", 20, 20)


def _recording(
    render: Callable[[str], Response | None], seen: list[str], deny_at: int = 0
) -> DetectCtx:
    """
    Args:
        render (Callable[[str], Response | None]): The target.
        seen (list[str]): Every value sent is appended to it.
        deny_at (int): The 1-based request that ``send`` refuses (``None``); 0 refuses none.

    Returns:
        DetectCtx: A context that records the values and refuses one request.
    """
    return _ctx(lambda v: None if seen.append(v) or len(seen) == deny_at else render(v))


_CMD = InjectionPoint("GET", "https://example.com/run", "cmd", "ls", (("cmd", "ls"),))


async def test_a_canary_point_tries_the_first_forms_and_a_command_point_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plain field gets ``CANARY_LIMIT`` forms; a command-shaped one gets every form."""
    forms = _fixed(monkeypatch)
    assert len(forms) > ssti.CANARY_LIMIT
    for point, sent in ((_PLAIN, forms[: ssti.CANARY_LIMIT]), (_CMD, forms)):
        seen: list[str] = []
        assert await ssti.detect(point, _baseline(), _recording(_reflect, seen)) == []
        assert seen == [point.original + v for v in (payloads.SSTI_POLYGLOT, *(e for _, e in sent))]


async def test_the_engine_the_polyglot_names_is_tried_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Smarty error moves the Smarty form, last but one in the catalog, into the canary."""
    forms = _fixed(monkeypatch)
    smarty = [e for hint, e in forms if "Smarty" in hint]
    assert smarty and forms.index(("Smarty", smarty[0])) >= ssti.CANARY_LIMIT

    def render(value: str) -> Response:
        if payloads.SSTI_POLYGLOT in value:
            return _resp("Smarty error: syntax error in template", status=500)
        return _reflect(value)

    seen: list[str] = []
    assert await ssti.detect(_PLAIN, _baseline(), _recording(render, seen)) == []
    assert seen[1] == _PLAIN.original + smarty[0]
    assert len(seen) == 1 + ssti.CANARY_LIMIT


def test_engine_first_moves_the_named_forms_and_keeps_every_other() -> None:
    """The named engine's forms lead; the rest follow in catalog order, none lost or doubled."""
    forms = payloads.arith_payloads("wvabc", 2, 3)
    ordered = ssti.engine_first(forms, "Twig")
    named = tuple(pair for pair in forms if "Twig" in pair[0])
    assert len(named) == 2
    assert ordered == named + tuple(pair for pair in forms if pair not in named)


async def test_a_denied_arithmetic_request_stops_the_detector() -> None:
    """A ``None`` after the polyglot ends the loop: nothing is sent after it."""
    seen: list[str] = []
    assert await ssti.detect(_POINT, _baseline(), _recording(_reflect, seen, deny_at=2)) == []
    assert len(seen) == 2


def _twig(value: str) -> Response:
    """
    A target that evaluates ``{{a*b}}`` and multiplies ``7*'7'`` as numbers, like Twig.

    Args:
        value (str): The injected value.

    Returns:
        Response: The evaluated product, or a page with no expression in it.
    """
    arith = _JINJA_ARITH.search(value)
    if arith:
        return _resp(f"<p>{arith.group(1)}{int(arith.group(2)) * int(arith.group(3))}</p>")
    string = _JINJA_STR.search(value)
    if string:
        return _resp(f"<p>{string.group(1)}49</p>")
    return _resp("<p>Hi</p>")


async def test_the_string_probe_names_the_engine() -> None:
    """``7777777`` is Jinja2/Nunjucks, ``49`` is Twig, anything else leaves it unknown."""

    def neither(value: str) -> Response:
        if _JINJA_STR.search(value):
            return _resp("<p>Hi</p>")
        return _twig(value)

    cases = (
        (lambda v: _jinja(v, raise_on_polyglot=False), "Jinja2/Nunjucks"),
        (_twig, "Twig"),
        (neither, "engine unknown"),
    )
    for render, engine in cases:
        (hit,) = await ssti.detect(_POINT, _baseline(), _ctx(render))
        assert f"({engine})" in hit.title, engine


async def test_a_denied_string_probe_still_reports_the_hit_with_the_engine_unknown() -> None:
    """The arithmetic already proved the injection; only the engine's name is missing."""
    seen: list[str] = []
    jinja = _recording(lambda v: _jinja(v, raise_on_polyglot=False), seen, deny_at=3)
    (hit,) = await ssti.detect(_POINT, _baseline(), jinja)
    assert "(engine unknown)" in hit.title
    assert len(seen) == 3


async def test_an_engine_error_already_in_the_baseline_does_not_name_the_engine() -> None:
    """A Twig error the page always shows is not the polyglot's doing: the string probe decides."""
    twig_error = "Twig\\Error\\SyntaxError: Unexpected token"

    def render(value: str) -> Response:
        if payloads.SSTI_POLYGLOT in value:
            return _resp(twig_error)
        return _jinja(value, raise_on_polyglot=False)

    (hit,) = await ssti.detect(_POINT, _baseline(), _ctx(render))
    assert "(Twig)" in hit.title  # control: a new error names the engine
    (hit,) = await ssti.detect(_POINT, _baseline(f"<p>{twig_error}</p>"), _ctx(render))
    assert "(Jinja2/Nunjucks)" in hit.title
