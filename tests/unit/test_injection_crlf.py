"""
CRLF-injection detector — spec 012 RF-01, RF-02, RF-15, ADR-5.

Pure detector unit: ``_ctx`` wraps a ``render`` callable as the scanner's
``send``. Each test decides what headers / body the target returns for a payload.
A hit needs an injected *header* ``httpx`` parsed back (or a full body split), not
a body-text reflection.
"""

from __future__ import annotations

import re
from collections.abc import Callable

import httpx

from webvigil.checks.injection.detect import DetectCtx, crlf, normalize_body
from webvigil.checks.injection.models import Baseline, InjectionPoint
from webvigil.core.findings import Confidence, Severity
from webvigil.http.client import Response

_POINT = InjectionPoint("GET", "https://example.com/set-lang", "lang", "en", (("lang", "en"),))
_PLAIN = InjectionPoint("GET", "https://example.com/x", "note", "hi", (("note", "hi"),))

_TOKEN_RE = re.compile(r"X-WvInjected: ([0-9a-f]+)", re.I)
_COOKIE_RE = re.compile(r"Set-Cookie: (wv[0-9a-f]+=1)")


def _resp(text: str = "ok", *, headers: dict[str, str] | None = None) -> Response:
    return Response(
        url="https://example.com/set-lang",
        requested_url="https://example.com/set-lang",
        status_code=200,
        headers=httpx.Headers(headers or {"content-type": "text/plain"}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
    )


def _baseline(body: str = "lang is en") -> Baseline:
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


def _splitting_server(value: str) -> Response:
    """A permissive server: an injected header line in the value comes back as a real header."""
    headers = {"content-type": "text/plain"}
    m = _TOKEN_RE.search(value)
    if m:
        headers["X-WvInjected"] = m.group(1)
    c = _COOKIE_RE.search(value)
    if c:
        headers["set-cookie"] = c.group(1)
    if "\r\n\r\n<html>" in value:
        body = value.split("\r\n\r\n", 1)[1]
        return _resp(body, headers=headers)
    return _resp(f"lang set to {value.splitlines()[0]}", headers=headers)


async def test_injected_header_parsed_back_is_a_high_hit() -> None:
    """An ``X-WvInjected`` header the server sent back is a HIGH CRLF hit."""
    hits = await crlf.detect(_POINT, _baseline(), _ctx(_splitting_server))
    assert len(hits) == 1
    hit = hits[0]
    assert hit.kind == "crlf"
    assert hit.check_id == "injection.crlf"
    assert hit.severity is Severity.HIGH
    assert hit.confidence is Confidence.HIGH
    assert "CRLF" in hit.title


async def test_set_cookie_split_is_a_high_hit() -> None:
    """A ``Set-Cookie: wv…=1`` the server echoed is a HIGH hit."""

    def render(value: str) -> Response:
        c = _COOKIE_RE.search(value)
        return _resp("ok", headers={"set-cookie": c.group(1)} if c else {})

    hits = await crlf.detect(_POINT, _baseline(), _ctx(render))
    assert hits and hits[0].kind == "crlf"
    assert any("Set-Cookie" in label for label, _ in hits[0].evidence)


async def test_full_body_split_is_a_high_hit() -> None:
    """A double-CRLF payload whose marker becomes the whole response body is a HIGH hit."""

    def body_only(value: str) -> Response:
        if "\r\n\r\n<html>" in value:
            return _resp(value.split("\r\n\r\n", 1)[1])
        return _resp("nothing reflected")

    hits = await crlf.detect(_POINT, _baseline(), _ctx(body_only))
    assert len(hits) == 1
    assert "body split" in " ".join(label for label, _ in hits[0].evidence).lower()


async def test_payload_reflected_in_body_text_only_is_not_a_hit() -> None:
    """The payload echoed into the page body (not a header) is not a CRLF hit."""
    hits = await crlf.detect(_POINT, _baseline(), _ctx(lambda v: _resp(f"you asked for {v}")))
    assert hits == []


async def test_header_the_target_always_sets_is_suppressed() -> None:
    """A target that always returns X-WvInjected with our token is not a new signal."""

    def render(value: str) -> Response:
        m = _TOKEN_RE.search(value)
        return _resp(
            "ok", headers={"X-WvInjected": m.group(1)} if m else {"X-WvInjected": "static"}
        )

    hits = await crlf.detect(_POINT, _baseline(), _ctx(render))
    assert hits == []


async def test_non_headerlike_point_gets_the_canary_set() -> None:
    """A ``note`` point only sends the first two CRLF payloads, not the full set."""
    seen: list[str] = []

    def render(value: str) -> Response:
        seen.append(value)
        return _resp("nothing")

    await crlf.detect(_PLAIN, _baseline(), _ctx(render))
    payloads_sent = [v for v in seen if v != _PLAIN.original]
    assert len(payloads_sent) == 2  # canary (a full run would send 6)


async def test_detector_stops_when_send_returns_none() -> None:
    calls = 0

    def render(value: str) -> Response | None:
        nonlocal calls
        calls += 1
        return None if calls >= 3 else _resp("ok")

    hits = await crlf.detect(_POINT, _baseline(), _ctx(render))
    assert hits == []
    assert calls == 3  # own baseline + one payload, then None
