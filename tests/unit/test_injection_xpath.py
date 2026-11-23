"""
XPath-injection detector — spec 014 RF-09, RF-17.

Pure detector unit: ``_ctx`` renders keyed on the sent value. The error probe
runs first; the boolean probe needs a two-sided split (TRUE tracks the baseline,
FALSE diverges) that reproduces.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx2

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx, normalize_body, xpath
from webvigil.checks.injection.models import Baseline, InjectionPoint
from webvigil.checks.injection.points import is_xpathlike
from webvigil.core.findings import Confidence, Severity
from webvigil.http.client import Response

_POINT = InjectionPoint("GET", "https://example.com/xdoc", "node", "Dune", (("node", "Dune"),))
_BASE_BODY = "<book><title>Dune</title></book>"
_FALSE_BODY = "<empty/>"


def _resp(text: str, *, status: int = 200) -> Response:
    return Response(
        url="https://example.com/xdoc",
        requested_url="https://example.com/xdoc",
        status_code=status,
        headers=httpx2.Headers({"content-type": "application/xml"}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
    )


def _baseline(body: str = _BASE_BODY) -> Baseline:
    return Baseline(200, body, normalize_body(body), len(body), 1.0)


def _ctx(render: Callable[[str], Response | None]) -> DetectCtx:
    async def send(
        point: InjectionPoint,
        value: str,
        *,
        time_based: bool = False,
        content_type: str | None = None,
    ) -> Response | None:
        return render(value)

    return DetectCtx(send=send, delay_s=5, host="example.com")


async def test_expression_error_signature_is_a_high_hit() -> None:
    """An XPath parser error absent from the baseline is HIGH / HIGH."""
    hits = await xpath.detect(
        _POINT,
        _baseline(),
        _ctx(lambda v: _resp("lxml.etree.XPathEvalError: Invalid expression", status=500)),
    )
    assert len(hits) == 1
    assert hits[0].kind == "xpath"
    assert hits[0].check_id == "injection.xpath"
    assert hits[0].severity is Severity.HIGH
    assert hits[0].confidence is Confidence.HIGH


async def test_boolean_split_that_reproduces_is_a_medium_hit() -> None:
    """TRUE tracks the baseline, FALSE returns an empty node set, reproduced -> MEDIUM."""

    def render(v: str) -> Response:
        if "1'='1" in v or "1=1" in v:
            return _resp(_BASE_BODY)
        if "1'='2" in v or "1=2" in v:
            return _resp(_FALSE_BODY)
        return _resp(_BASE_BODY)

    hits = await xpath.detect(_POINT, _baseline(), _ctx(render))
    assert len(hits) == 1
    assert hits[0].severity is Severity.MEDIUM
    assert hits[0].confidence is Confidence.MEDIUM


async def test_bare_5xx_with_no_signature_is_not_a_hit() -> None:
    """A 500 with no XPath signature and no boolean split is not a hit."""
    hits = await xpath.detect(
        _POINT, _baseline(), _ctx(lambda v: _resp("Server Error", status=500))
    )
    assert hits == []


async def test_one_sided_change_is_not_a_hit() -> None:
    """FALSE staying close to the baseline (only TRUE moved) is not a split."""

    def render(v: str) -> Response:
        if "1'='1" in v or "1=1" in v:
            return _resp("a wholly different document " * 20)
        return _resp(_BASE_BODY)

    assert await xpath.detect(_POINT, _baseline(), _ctx(render)) == []


def test_is_xpathlike_matches_only_distinctly_xpath_names() -> None:
    """``node`` / ``xpath`` / ``xquery`` are front-loaded; a generic ``id`` is not."""
    assert is_xpathlike(_POINT) is True
    other = InjectionPoint("GET", "https://example.com/x", "id", "1", (("id", "1"),))
    assert is_xpathlike(other) is False


def _split(value: str) -> Response:
    """
    Args:
        value (str): The injected value.

    Returns:
        Response: The baseline page for a TRUE payload, an empty node set for a FALSE one.
    """
    if "1'='2" in value or "1=2" in value:
        return _resp(_FALSE_BODY)
    return _resp(_BASE_BODY)


def _counting(render: Callable[[str], Response], seen: list[str], deny_at: int = 0) -> DetectCtx:
    """
    Args:
        render (Callable[[str], Response]): The target.
        seen (list[str]): Every value sent is appended to it.
        deny_at (int): The 1-based request that ``send`` refuses (``None``); 0 refuses none.

    Returns:
        DetectCtx: A context that records the values and refuses one request.
    """
    return _ctx(lambda v: None if seen.append(v) or len(seen) == deny_at else render(v))


_ERRORS = len(payloads.XPATH_ERROR)


async def test_a_denied_request_at_each_stage_stops_the_detector() -> None:
    """An error probe, either side of a pair or of its repeat: nothing goes out after that pair."""
    for deny_at, sent in (
        (2, 2),
        (_ERRORS + 1, _ERRORS + 2),  # the two sides of a pair go out together
        (_ERRORS + 2, _ERRORS + 2),
        (_ERRORS + 3, _ERRORS + 4),
        (_ERRORS + 4, _ERRORS + 4),
    ):
        seen: list[str] = []
        assert await xpath.detect(_POINT, _baseline(), _counting(_split, seen, deny_at)) == []
        assert len(seen) == sent, deny_at
    seen = []
    assert await xpath.detect(_POINT, _baseline(), _counting(_split, seen))  # control
    assert len(seen) == _ERRORS + 4


async def test_a_page_with_no_split_sends_each_pair_once() -> None:
    """The repeat runs only after a split: a flat page costs the probes and one pass of pairs."""
    seen: list[str] = []
    assert (
        await xpath.detect(_POINT, _baseline(), _counting(lambda v: _resp(_BASE_BODY), seen)) == []
    )
    assert len(seen) == _ERRORS + 2 * len(payloads.XPATH_BOOLEAN_PAIRS)


async def test_a_split_that_does_not_reproduce_is_not_a_hit() -> None:
    """FALSE answering an empty node set once, then the baseline page, is noise."""
    falses = {"n": 0}

    def render(value: str) -> Response:
        if "1'='2" in value or "1=2" in value:
            falses["n"] += 1
            return _resp(_FALSE_BODY if falses["n"] % 2 else _BASE_BODY)
        return _resp(_BASE_BODY)

    assert await xpath.detect(_POINT, _baseline(), _ctx(render)) == []
    assert falses["n"] == 2 * len(payloads.XPATH_BOOLEAN_PAIRS)


async def test_an_error_signature_already_in_the_baseline_is_not_a_hit() -> None:
    """The parser error must be new; the same page before injection does not count."""
    error = "lxml.etree.XPathEvalError: Invalid expression"
    assert await xpath.detect(_POINT, _baseline(), _ctx(lambda v: _resp(error)))  # control
    assert await xpath.detect(_POINT, _baseline(error), _ctx(lambda v: _resp(error))) == []
