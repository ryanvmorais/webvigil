"""
XPath-injection detector — spec 014 RF-09, RF-17.

Pure detector unit: ``_ctx`` renders keyed on the sent value. The error probe
runs first; the boolean probe needs a two-sided split (TRUE tracks the baseline,
FALSE diverges) that reproduces.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

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
        headers=httpx.Headers({"content-type": "application/xml"}),
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
