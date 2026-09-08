"""
SQL-injection detectors — spec 006 RF-09, RF-13.

Pure detector units, one section per technique: ``_ctx`` wraps a ``render``
callable as the scanner's ``send``, so each test decides what the target returns
for a payload — an error string, a true/false page pair, or an ``elapsed_ms``
that scales with the requested sleep — and no HTTP is issued.
"""

from __future__ import annotations

import re
from collections.abc import Callable

import httpx

from webvigil.checks.injection.detect import DetectCtx, normalize_body, sqli
from webvigil.checks.injection.models import Baseline, InjectionPoint
from webvigil.http.client import Response

_POINT = InjectionPoint("GET", "https://example.com/item", "id", "1", (("id", "1"),))

_Render = Callable[[str], Response | None]


def _resp(text: str, *, elapsed_ms: float = 5.0) -> Response:
    """
    Args:
        text (str): The response body.
        elapsed_ms (float): The wall time to report — how time-based detection
            sees a delay.

    Returns:
        Response: A 200 ``text/html`` response.
    """
    return Response(
        url="https://example.com/item",
        requested_url="https://example.com/item",
        status_code=200,
        headers=httpx.Headers({"content-type": "text/html"}),
        text=text,
        content=text.encode(),
        elapsed_ms=elapsed_ms,
    )


def _baseline(body: str = "<div>Widget</div>", elapsed_ms: float = 5.0) -> Baseline:
    """
    Args:
        body (str): The pre-injection response body.
        elapsed_ms (float): The pre-injection wall time.

    Returns:
        Baseline: The baseline each payload is compared against.
    """
    return Baseline(200, body, normalize_body(body), len(body), elapsed_ms)


def _ctx(render: _Render, *, delay_s: int = 5) -> DetectCtx:
    """
    Args:
        render (_Render): Maps an injected value to the target's response (or
            ``None`` to model a denied request).
        delay_s (int): The time-based probe delay the detector should use.

    Returns:
        DetectCtx: A detector context whose ``send`` calls ``render``.
    """

    async def send(
        point: InjectionPoint, value: str, *, time_based: bool = False
    ) -> Response | None:
        return render(value)

    return DetectCtx(send=send, delay_s=delay_s, host="example.com")


# ---------------------------------------------------------------------------
# Error-based
# ---------------------------------------------------------------------------


async def test_error_based_detects_each_dbms() -> None:
    """The five DBMS error signatures each match and name their DBMS in the title."""
    cases = {
        "MySQL": "You have an error in your SQL syntax; check the manual for your MySQL",
        "PostgreSQL": "org.postgresql.util.PSQLException: ERROR: unterminated quoted string",
        "MSSQL": "Unclosed quotation mark after the character string",
        "Oracle": "ORA-01756: quoted string not properly terminated",
        "SQLite": 'sqlite3.OperationalError: near "\'": syntax error',
    }
    for dbms, error in cases.items():

        def render(value: str, err: str = error) -> Response:
            return _resp(err if value.endswith("'") else "<div>Widget</div>")

        hits = await sqli.detect_error(_POINT, _baseline(), _ctx(render))
        assert len(hits) == 1, dbms
        assert dbms in hits[0].title


async def test_error_signature_already_in_the_baseline_is_not_a_hit() -> None:
    """An error string that was already in the baseline body is not attributed to us."""
    error = "ORA-01756: quoted string not properly terminated"
    hits = await sqli.detect_error(_POINT, _baseline(error), _ctx(lambda v: _resp(error)))
    assert hits == []


# ---------------------------------------------------------------------------
# Boolean-based
# ---------------------------------------------------------------------------


def _boolean_render(true_like: str, false_like: str) -> _Render:
    """
    Args:
        true_like (str): Body returned for the baseline and the always-true payload.
        false_like (str): Body returned for the ``1=2`` / ``'1'='2`` payloads.

    Returns:
        _Render: A render function modelling a boolean-injectable endpoint.
    """

    def render(value: str) -> Response:
        if value == "1":  # baseline restatement
            return _resp(true_like)
        if "1=2" in value or "'1'='2" in value:
            return _resp(false_like)
        return _resp(true_like)

    return render


async def test_boolean_based_clean_positive() -> None:
    """A stable true-page / false-page split is a boolean-SQLi hit."""
    body = "<div>Widget A</div><div>Widget B</div>"
    hits = await sqli.detect_boolean(
        _POINT, _baseline(body), _ctx(_boolean_render(body, "<div>No results</div>"))
    )
    assert len(hits) == 1 and hits[0].kind == "sqli-boolean"


async def test_boolean_based_unstable_baseline_is_rejected() -> None:
    """If the baseline restatement is not stable, no boolean conclusion is drawn."""
    calls = {"n": 0}

    def render(value: str) -> Response:
        calls["n"] += 1
        if value == "1":  # every restatement returns something different
            return _resp(f"<p>time {calls['n']}</p>" + "z" * 400)
        if "1=2" in value or "'1'='2" in value:
            return _resp("<div>nope</div>")
        return _resp("<div>Widget</div>")

    hits = await sqli.detect_boolean(_POINT, _baseline("<div>Widget</div>"), _ctx(render))
    assert hits == []


async def test_boolean_based_always_different_is_rejected() -> None:
    """An endpoint whose every response differs gives no true/false signal."""
    hits = await sqli.detect_boolean(
        _POINT, _baseline("<div>Widget</div>"), _ctx(lambda v: _resp(f"<div>{v}</div>"))
    )
    assert hits == []


# ---------------------------------------------------------------------------
# Time-based
# ---------------------------------------------------------------------------


def _time_render(value: str) -> Response:
    """A target whose response time grows one second per requested sleep-second.

    Args:
        value (str): The injected payload.

    Returns:
        Response: A response whose ``elapsed_ms`` scales with the sleep in ``value``.
    """
    match = re.search(r"(?:SLEEP|pg_sleep|DELAY '0:0:)\(?(\d+)", value)
    seconds = int(match.group(1)) if match else 0
    return _resp("<div>Widget</div>", elapsed_ms=100.0 + seconds * 1000)


async def test_time_based_injected_delay_is_a_hit() -> None:
    """A delay that scales with the requested sleep is a HIGH-confidence time-based hit."""
    hits = await sqli.detect_time(_POINT, _baseline(), _ctx(_time_render))
    assert len(hits) == 1 and hits[0].kind == "sqli-time"
    assert hits[0].confidence.name == "HIGH"


async def test_time_based_uniformly_slow_target_is_not_a_hit() -> None:
    """A target that is simply slow for every request does not scale, so no hit."""
    hits = await sqli.detect_time(
        _POINT,
        _baseline(elapsed_ms=5200.0),
        _ctx(lambda v: _resp("<div>Widget</div>", elapsed_ms=5200.0)),
    )
    assert hits == []


async def test_time_based_non_scaling_spike_is_not_a_hit() -> None:
    """A fixed spike that does not grow with the requested sleep is rejected."""

    def render(value: str) -> Response:
        if re.search(r"(?:SLEEP|pg_sleep)\(0\)|DELAY '0:0:0'", value):
            return _resp("<div>Widget</div>", elapsed_ms=100.0)
        return _resp("<div>Widget</div>", elapsed_ms=5200.0)  # every real delay spikes the same

    hits = await sqli.detect_time(_POINT, _baseline(), _ctx(render))
    assert hits == []
