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

from webvigil.checks.injection import payloads
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
    # the echo proof, not a later time-stage hit (the shell also sleeps)
    assert hit.title == "OS command injection via the 'host' parameter"


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
    assert hits[0].confidence is Confidence.HIGH  # the half-delay confirmation scaled too
    assert hits[0].title == "OS command injection (time-based, POSIX) via the 'host' parameter"


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


# ---------------------------------------------------------------------------
# Which payloads go out, and where a failed request ends the routine
# ---------------------------------------------------------------------------


def _timed(elapsed_by_delay: dict[int, float]) -> Callable[[str], Response]:
    """
    Args:
        elapsed_by_delay (dict[int, float]): The response time (ms) for each slept second
            count; a count not in the table (and a value with no sleep) answers in 5 ms.

    Returns:
        Callable[[str], Response]: A render for a blind shell with that timing.
    """

    def render(value: str) -> Response:
        sleep = _SLEEP.search(value)
        secs = int(next(g for g in sleep.groups() if g)) if sleep else 0
        return _resp("done", elapsed_ms=elapsed_by_delay.get(secs, 5.0))

    return render


@pytest.mark.parametrize(
    ("point", "templates"),
    [(_POINT, payloads.CMDI_ECHO_POSIX), (_PLAIN, cmdi._ECHO_CANARY)],
    ids=["shell-name", "plain-name"],
)
async def test_the_echo_set_depends_on_the_parameter_name(
    point: InjectionPoint, templates: tuple[str, ...]
) -> None:
    """A shell-shaped name gets the full POSIX set, any other name the short canary set."""
    seen: list[str] = []

    def render(value: str) -> Response:
        seen.append(value)
        return _resp("PING host")

    assert await cmdi.detect(point, _baseline(), _ctx(render, time_based_cmdi=False)) == []
    marker = re.compile(r"wv[0-9a-f]+|\d+")
    sent = [marker.sub("N", v.removeprefix(point.original)) for v in seen]
    expected = [marker.sub("N", t.format(marker="wv0", a=1, b=1)) for t in templates]
    assert sent[: len(templates)] == expected
    assert len(seen) == len(templates) + len(payloads.CMDI_ECHO_WINDOWS)


async def test_a_plain_name_gets_no_time_stage_even_when_it_is_on() -> None:
    """The sleep payloads are for shell-shaped names only: a ``note`` that sleeps is not probed."""
    seen: list[str] = []

    def render(value: str) -> Response:
        seen.append(value)
        return _blind_shell(value)

    assert await cmdi.detect(_PLAIN, _baseline(), _ctx(render)) == []
    assert seen  # the echo stage ran
    assert not any(_SLEEP.search(v) for v in seen)


@pytest.mark.parametrize(
    "failed", range(len(payloads.CMDI_ECHO_POSIX) + len(payloads.CMDI_ECHO_WINDOWS))
)
async def test_one_failed_echo_request_ends_the_echo_stage(failed: int) -> None:
    """A ``None`` at any POSIX or Windows echo request ends the stage: nothing after it."""
    calls: list[str] = []

    def render(value: str) -> Response | None:
        calls.append(value)
        return None if len(calls) - 1 == failed else _resp("PING host")

    assert await cmdi.detect(_POINT, _baseline(), _ctx(render, time_based_cmdi=False)) == []
    assert len(calls) == failed + 1


async def test_a_failed_time_control_ends_the_time_stage() -> None:
    """The 0-second control of the first template denied: no delayed request follows."""
    echoes = len(payloads.CMDI_ECHO_POSIX) + len(payloads.CMDI_ECHO_WINDOWS)
    calls: list[str] = []

    def render(value: str) -> Response | None:
        calls.append(value)
        return None if len(calls) - 1 == echoes else _resp("PING host")

    assert await cmdi.detect(_POINT, _baseline(), _ctx(render)) == []
    assert len(calls) == echoes + 1
    assert calls[-1].endswith(";sleep 0")


# ---------------------------------------------------------------------------
# The Windows proof and the time stage at their edges
# ---------------------------------------------------------------------------


async def test_a_marker_the_baseline_already_shows_is_no_windows_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The marker on the page before injection says nothing, even with the product after it."""
    _fix_the_dice(monkeypatch, "ab0cde5e6f01", 37, 52)  # 37 * 52 = 1924
    baseline = _baseline("PING wvab0cde5e6f01 usage")

    def render(value: str) -> Response:
        return _resp("PING\nwvab0cde5e6f01\n1924\n" if _WIN_ARITH.search(value) else "PING")

    assert await cmdi.detect(_PLAIN, baseline, _ctx(render, time_based_cmdi=False)) == []


async def test_the_product_without_the_marker_is_no_windows_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The product alone (the marker never echoed) is no proof, wherever it sits on the page."""
    _fix_the_dice(monkeypatch, "ab0cde5e6f01", 37, 52)

    def render(value: str) -> Response:
        return _resp("x" * 20 + " 1924 results" if _WIN_ARITH.search(value) else "PING")

    assert await cmdi.detect(_PLAIN, _baseline(), _ctx(render, time_based_cmdi=False)) == []


async def test_a_delay_of_exactly_the_threshold_is_a_time_hit() -> None:
    """The injected request must be ``delay - 1`` seconds slower: exactly that is enough."""
    # delay 5 s: threshold 4,000 ms over the 5 ms floor; the half delay (2 s) lands in 1-4 s
    hits = await cmdi.detect(_POINT, _baseline(), _ctx(_timed({5: 4005.0, 2: 2005.0})))
    assert [h.confidence for h in hits] == [Confidence.HIGH]


async def test_a_delay_short_of_the_threshold_is_not_rescued_by_the_confirmation() -> None:
    """A 5 s sleep answered 3.9 s late fails, though the 2 s probe alone would look right."""
    assert await cmdi.detect(_POINT, _baseline(), _ctx(_timed({5: 3905.0, 2: 2005.0}))) == []


async def test_a_confirmation_that_does_not_scale_is_not_a_time_hit() -> None:
    """Slow on any sleep (5 s and 2 s both 5 s late) is not the delay we asked for."""
    render = _timed({5: 5005.0, 6: 5005.0, 2: 5005.0, 3: 5005.0})
    assert await cmdi.detect(_POINT, _baseline(), _ctx(render)) == []


async def test_a_denied_confirmation_is_a_medium_time_hit() -> None:
    """With the half-delay request denied, the delay alone gives a MEDIUM-confidence hit."""
    delayed = 0

    async def send(
        point: InjectionPoint, value: str, *, time_based: bool = False
    ) -> Response | None:
        nonlocal delayed
        if time_based:
            delayed += 1
            if delayed == 2:  # the first template's half-delay confirmation
                return None
        return _blind_shell(value)

    ctx = DetectCtx(send=send, delay_s=5, host="example.com", time_based_cmdi=True)
    hits = await cmdi.detect(_POINT, _baseline(), ctx)
    assert [(h.severity, h.confidence) for h in hits] == [(Severity.CRITICAL, Confidence.MEDIUM)]
    assert delayed == 2


# ---------------------------------------------------------------------------
# The evidence excerpt
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "excerpt"),
    [
        ("PING\nwvabcdef=400\nrest", "wvabcdef=400"),  # the line, not the page
        ("PING\nwvabcdef=400", "wvabcdef=400"),  # the last line keeps its last character
        ("x" * 188 + "wvabcdef=400", "x" * 188 + "wvabcdef=400"),  # 200 characters: no cut
        ("x" * 189 + "wvabcdef=400", "x" * 189 + "wvabcdef=40…"),  # 201: cut and marked
    ],
    ids=["middle-line", "last-line", "at-limit", "over-limit"],
)
async def test_the_command_output_is_the_line_with_the_proof(
    monkeypatch: pytest.MonkeyPatch, body: str, excerpt: str
) -> None:
    """The evidence is the single line that holds the needle, cut at 200 characters."""
    monkeypatch.setattr(
        "webvigil.checks.injection.detect.cmdi.secrets.token_hex", lambda n: "abcdef"
    )
    monkeypatch.setattr("webvigil.checks.injection.detect.cmdi.random.randint", lambda lo, hi: 20)
    ctx = _ctx(lambda v: _resp(body), time_based_cmdi=False)
    hits = await cmdi.detect(_POINT, _baseline(), ctx)
    assert dict(hits[0].evidence)["Command output"] == excerpt
