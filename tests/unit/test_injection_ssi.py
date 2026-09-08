"""
SSI / ESI-injection detector — spec 014 RF-10, RF-17, ADR-8.

Pure detector unit: ``_ctx`` renders keyed on the sent value and records every
payload for the "no #exec / #include" assertion.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

from webvigil.checks.injection.detect import DetectCtx, normalize_body, ssi
from webvigil.checks.injection.models import Baseline, InjectionPoint
from webvigil.checks.injection.points import is_ssilike
from webvigil.core.findings import Confidence, Severity
from webvigil.http.client import Response

_POINT = InjectionPoint("GET", "https://example.com/page", "tpl", "hi", (("tpl", "hi"),))
_BASE_BODY = "<div>hi</div>"


def _resp(text: str) -> Response:
    return Response(
        url="https://example.com/page",
        requested_url="https://example.com/page",
        status_code=200,
        headers=httpx.Headers({"content-type": "text/html"}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
    )


def _baseline(body: str = _BASE_BODY) -> Baseline:
    return Baseline(200, body, normalize_body(body), len(body), 1.0)


def _ctx(render: Callable[[str], Response | None], *, seen: list[str] | None = None) -> DetectCtx:
    async def send(
        point: InjectionPoint,
        value: str,
        *,
        time_based: bool = False,
        content_type: str | None = None,
    ) -> Response | None:
        if seen is not None:
            seen.append(value)
        return render(value)

    return DetectCtx(send=send, delay_s=5, host="example.com")


async def test_evaluated_directive_output_is_a_high_hit() -> None:
    """A rendered date the baseline never had is HIGH / HIGH."""
    hits = await ssi.detect(
        _POINT, _baseline(), _ctx(lambda v: _resp("<div>Mon, 08 Sep 2026 12:00:00 UTC</div>"))
    )
    assert len(hits) == 1
    assert hits[0].kind == "ssi"
    assert hits[0].check_id == "injection.ssi"
    assert hits[0].severity is Severity.HIGH
    assert hits[0].confidence is Confidence.HIGH


async def test_printenv_dump_is_a_high_hit() -> None:
    """An environment dump (``DOCUMENT_ROOT=...``) is evaluated output."""
    hits = await ssi.detect(
        _POINT, _baseline(), _ctx(lambda v: _resp("<pre>DOCUMENT_ROOT=/var/www\nHTTP_HOST=x</pre>"))
    )
    assert len(hits) == 1
    assert hits[0].severity is Severity.HIGH


async def test_ssi_error_string_is_a_medium_hit() -> None:
    """The SSI processor's undefined-variable error is MEDIUM / MEDIUM."""

    def render(v: str) -> Response:
        if 'var="wv' in v:
            return _resp("<div>[an error occurred while processing this directive]</div>")
        return _resp(_BASE_BODY)

    hits = await ssi.detect(_POINT, _baseline(), _ctx(render))
    assert len(hits) == 1
    assert hits[0].severity is Severity.MEDIUM
    assert hits[0].confidence is Confidence.MEDIUM


async def test_directive_reflected_verbatim_is_not_a_hit() -> None:
    """An endpoint that echoes the directive without evaluating it is not a hit."""
    hits = await ssi.detect(_POINT, _baseline(), _ctx(lambda v: _resp(f"<div>{v}</div>")))
    assert hits == []


async def test_detector_never_sends_exec_or_include() -> None:
    """No payload the detector sends carries ``#exec`` or ``#include`` (ADR-8)."""
    seen: list[str] = []
    await ssi.detect(_POINT, _baseline(), _ctx(lambda v: _resp(_BASE_BODY), seen=seen))
    joined = " ".join(seen).lower()
    assert "#exec" not in joined
    assert "#include" not in joined
    assert seen  # the detector did send something


def test_is_ssilike_matches_page_parameter_names() -> None:
    """``tpl`` / ``page`` / ``include`` are front-loaded; ``colour`` is not."""
    assert is_ssilike(_POINT) is True
    other = InjectionPoint("GET", "https://example.com/x", "colour", "red", (("colour", "red"),))
    assert is_ssilike(other) is False
