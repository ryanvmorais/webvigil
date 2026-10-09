"""
OS command-injection detector — spec 011 RF-02, RF-03, RF-07, RF-14.

Pure detector unit: ``_ctx`` wraps a ``render`` callable as the scanner's
``send``, so each test decides what the target would return for a given payload.
``_vuln_shell`` stands in for a parameter concatenated into ``os.system`` — it
evaluates the ``$((a*b))`` arithmetic and, for a ``sleep`` / ``ping -n`` payload,
reports an elapsed time that scales with the delay. ``_reflect`` echoes the
payload verbatim (the app that only *reflects*, never executes).
"""

from __future__ import annotations

import re
from collections.abc import Callable

import httpx
import pytest

from webvigil.checks.injection.detect import DetectCtx, cmdi, normalize_body
from webvigil.checks.injection.models import Baseline, InjectionPoint
from webvigil.core.findings import Confidence, Severity
from webvigil.http.client import Response

_POINT = InjectionPoint("GET", "https://example.com/ping", "host", "localhost", (("host", "x"),))
_PLAIN = InjectionPoint("GET", "https://example.com/x", "note", "hi", (("note", "hi"),))

_ARITH = re.compile(r"(wv[0-9a-f]+)=\$\(\((\d+)\*(\d+)\)\)")
_WIN_ARITH = re.compile(r"(wv[0-9a-f]+)&set /a (\d+)\*(\d+)")
_SLEEP = re.compile(r"sleep (\d+)|ping -n (\d+)|timeout /t (\d+)")


def _resp(text: str, *, elapsed_ms: float = 5.0) -> Response:
    return Response(
        url="https://example.com/ping",
        requested_url="https://example.com/ping",
        status_code=200,
        headers=httpx.Headers({"content-type": "text/plain"}),
        text=text,
        content=text.encode(),
        elapsed_ms=elapsed_ms,
    )


def _baseline(body: str = "PING usage: ping host") -> Baseline:
    return Baseline(200, body, normalize_body(body), len(body), 5.0)


def _ctx(render: Callable[[str], Response | None], *, time_based_cmdi: bool = True) -> DetectCtx:
    async def send(
        point: InjectionPoint, value: str, *, time_based: bool = False
    ) -> Response | None:
        return render(value)

    return DetectCtx(send=send, delay_s=5, host="example.com", time_based_cmdi=time_based_cmdi)


def _vuln_shell(value: str) -> Response:
    """A parameter fed to a shell: evaluates $((a*b)), scales on sleep/ping."""
    sleep = _SLEEP.search(value)
    if sleep:
        secs = int(next(g for g in sleep.groups() if g))
        return _resp("PING ...", elapsed_ms=secs * 1000.0 + 5.0)
    posix = _ARITH.search(value)
    if posix:
        return _resp(f"PING\n{posix.group(1)}={int(posix.group(2)) * int(posix.group(3))}\n")
    win = _WIN_ARITH.search(value)
    if win:
        return _resp(f"PING\n{win.group(1)}\n{int(win.group(2)) * int(win.group(3))}\n")
    return _resp("PING host")


def _blind_shell(value: str) -> Response:
    """A shell-out with no useful output — only the timing side channel is observable."""
    sleep = _SLEEP.search(value)
    if sleep:
        secs = int(next(g for g in sleep.groups() if g))
        return _resp("done", elapsed_ms=secs * 1000.0 + 5.0)
    return _resp("done")


def _reflect(value: str) -> Response:
    """The app that echoes the parameter verbatim but never runs it."""
    return _resp(f"PING: unknown host '{value}'")


async def test_posix_arithmetic_echo_is_a_critical_hit() -> None:
    """``;echo <marker>=$((a*b))`` returning the computed product is CRITICAL / HIGH."""
    hits = await cmdi.detect(_POINT, _baseline(), _ctx(_vuln_shell))
    assert len(hits) == 1
    hit = hits[0]
    assert hit.kind == "cmdi"
    assert hit.check_id == "injection.cmdi.os"
    assert hit.severity is Severity.CRITICAL
    assert hit.confidence is Confidence.HIGH
    assert "command injection" in hit.title.lower()
    assert "host" in hit.title


async def test_reflected_payload_is_not_a_hit() -> None:
    """The literal ``$((a*b))`` echoed back, unevaluated, is not a hit."""
    hits = await cmdi.detect(_POINT, _baseline(), _ctx(_reflect, time_based_cmdi=False))
    assert hits == []


async def test_marker_without_the_product_is_not_a_hit() -> None:
    """The marker alone (reflection) without the evaluated product is not a hit."""

    def render(value: str) -> Response:
        m = _ARITH.search(value)
        return _resp(f"PING {m.group(1)} bad" if m else "PING")

    hits = await cmdi.detect(_POINT, _baseline(), _ctx(render, time_based_cmdi=False))
    assert hits == []


async def test_product_already_in_the_baseline_is_suppressed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A needle already present in the baseline body is not reported as new."""
    monkeypatch.setattr(
        "webvigil.checks.injection.detect.cmdi.secrets.token_hex", lambda n: "abcdef"
    )
    monkeypatch.setattr("webvigil.checks.injection.detect.cmdi.random.randint", lambda lo, hi: 20)
    needle = "wvabcdef=400"  # 20 * 20

    hits = await cmdi.detect(
        _POINT,
        _baseline(f"echo test {needle} done"),
        _ctx(lambda v: _resp(f"out {needle}"), time_based_cmdi=False),
    )
    assert hits == []


async def test_windows_set_a_variant_is_a_medium_hit() -> None:
    """Windows ``& echo <marker> & set /a a*b`` — marker then product — is CRITICAL / MEDIUM."""

    def render(value: str) -> Response | None:
        if _ARITH.search(value):
            return _resp("PING host")  # POSIX arithmetic does nothing here
        return _vuln_shell(value)

    hits = await cmdi.detect(_PLAIN, _baseline(), _ctx(render, time_based_cmdi=False))
    # _PLAIN is not command-shaped, so the POSIX canary runs, then the Windows set.
    assert len(hits) == 1
    assert hits[0].kind == "cmdi"
    assert hits[0].confidence is Confidence.MEDIUM


def _fix_the_dice(monkeypatch: pytest.MonkeyPatch, token: str, a: int, b: int) -> None:
    """
    Make the detector's random marker and operands known (they are drawn per call).

    Args:
        monkeypatch (pytest.MonkeyPatch): The fixture that undoes the patch.
        token (str): The hex digits ``secrets.token_hex`` returns, after the ``wv`` prefix.
        a (int): The first operand.
        b (int): The second operand.
    """
    operands = iter([a, b])
    monkeypatch.setattr("webvigil.checks.injection.detect.cmdi.secrets.token_hex", lambda n: token)
    monkeypatch.setattr(
        "webvigil.checks.injection.detect.cmdi.random.randint", lambda lo, hi: next(operands)
    )


async def test_the_digits_of_the_marker_are_not_the_product(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A page that only echoes the payload is not a hit when the marker holds the product (#177)."""
    _fix_the_dice(monkeypatch, "ab1924cd5e6f", 37, 52)  # 37 * 52 = 1924
    hits = await cmdi.detect(_PLAIN, _baseline(), _ctx(_reflect, time_based_cmdi=False))
    assert hits == []


async def test_a_product_that_is_part_of_a_longer_number_is_not_a_hit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the whole number counts: ``19240`` after the marker is not ``1924``."""
    _fix_the_dice(monkeypatch, "ab0cde5e6f01", 37, 52)

    def render(value: str) -> Response:
        win = _WIN_ARITH.search(value)
        return _resp(f"PING\n{win.group(1)}\n19240\n" if win else "PING host")

    hits = await cmdi.detect(_PLAIN, _baseline(), _ctx(render, time_based_cmdi=False))
    assert hits == []


async def test_a_number_the_page_already_shows_is_not_a_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A product that is on the baseline page too (a year, a count) says nothing new."""
    _fix_the_dice(monkeypatch, "ab0cde5e6f01", 45, 45)  # 2025
    baseline = _baseline("Copyright 2025 Example")

    def render(value: str) -> Response:
        win = _WIN_ARITH.search(value)
        return _resp(f"{win.group(1)}\nCopyright 2025 Example" if win else "PING host")

    assert await cmdi.detect(_PLAIN, baseline, _ctx(render, time_based_cmdi=False)) == []


async def test_the_windows_proof_still_holds_with_a_marker_that_has_other_digits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The product printed after the marker on the next line is still a MEDIUM hit."""
    _fix_the_dice(monkeypatch, "ab0cde5e6f01", 37, 52)

    def render(value: str) -> Response:
        return _resp("PING host") if _ARITH.search(value) else _vuln_shell(value)

    hits = await cmdi.detect(_PLAIN, _baseline(), _ctx(render, time_based_cmdi=False))
    assert len(hits) == 1 and hits[0].confidence is Confidence.MEDIUM


async def test_time_based_injected_delay_is_a_hit() -> None:
    """A ``sleep`` payload that scales the response time past a 0-delay control fires."""
    hits = await cmdi.detect(_POINT, _baseline(), _ctx(_blind_shell))
    assert len(hits) == 1
    assert hits[0].kind == "cmdi"
    assert hits[0].severity is Severity.CRITICAL
    assert "time-based" in hits[0].title


async def test_uniformly_slow_target_is_not_a_time_hit() -> None:
    """When the 0-delay control is just as slow, no timing conclusion is drawn."""
    hits = await cmdi.detect(_POINT, _baseline(), _ctx(lambda v: _resp("slow", elapsed_ms=6000.0)))
    assert hits == []


async def test_time_based_cmdi_off_sends_no_sleep_payload() -> None:
    """``time_based_cmdi=False`` skips the sleep stage entirely."""
    seen: list[str] = []

    def render(value: str) -> Response:
        seen.append(value)
        return _resp("PING host")

    hits = await cmdi.detect(_POINT, _baseline(), _ctx(render, time_based_cmdi=False))
    assert hits == []
    assert not any("sleep" in p or "ping -n" in p or "timeout /t" in p for p in seen)


async def test_detector_stops_when_send_returns_none() -> None:
    """A ``None`` from ``send`` (budget denied) stops the detector."""
    calls = 0

    def render(value: str) -> Response | None:
        nonlocal calls
        calls += 1
        return None if calls >= 2 else _resp("PING host")

    hits = await cmdi.detect(_POINT, _baseline(), _ctx(render, time_based_cmdi=False))
    assert hits == []
    assert calls == 2


async def test_time_stage_stops_when_the_sleep_budget_is_denied() -> None:
    """The sleep requests have their own sub-budget: a denied delayed request ends the stage."""
    seen: list[bool] = []

    async def send(
        point: InjectionPoint, value: str, *, time_based: bool = False
    ) -> Response | None:
        seen.append(time_based)
        return None if time_based else _resp("PING host")

    ctx = DetectCtx(send=send, delay_s=5, host="example.com", time_based_cmdi=True)
    assert await cmdi.detect(_POINT, _baseline(), ctx) == []
    assert seen.count(True) == 1  # the first delayed request was denied; none came after it
