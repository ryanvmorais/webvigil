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
_EMPTY_POINT = InjectionPoint("GET", "https://example.com/item", "id", "", (("id", ""),))

_Render = Callable[[str], Response | None]


def _resp(text: str, *, elapsed_ms: float = 5.0, status: int = 200) -> Response:
    """
    Args:
        text (str): The response body.
        elapsed_ms (float): The wall time to report — how time-based detection
            sees a delay.
        status (int): The response status. Defaults to 200.

    Returns:
        Response: A ``text/html`` response.
    """
    return Response(
        url="https://example.com/item",
        requested_url="https://example.com/item",
        status_code=status,
        headers=httpx.Headers({"content-type": "text/html"}),
        text=text,
        content=text.encode(),
        elapsed_ms=elapsed_ms,
    )


def _baseline(
    body: str = "<div>Widget</div>", elapsed_ms: float = 5.0, status: int = 200
) -> Baseline:
    """
    Args:
        body (str): The pre-injection response body.
        elapsed_ms (float): The pre-injection wall time.
        status (int): The pre-injection status. Defaults to 200.

    Returns:
        Baseline: The baseline each payload is compared against.
    """
    return Baseline(status, body, normalize_body(body), len(body), elapsed_ms)


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
# Boolean-based: same page in another status class, and a field that ships empty
# (issue #143)
# ---------------------------------------------------------------------------

# The shared layout is long, so the "no such row" page differs from the row page by a handful
# of bytes: the body similarity gate calls them the same page, only the status tells them apart.
_LAYOUT = "<html><body>" + "<p>layout</p>" * 300 + "{}</body></html>"
_ROW = _LAYOUT.format("<pre>ID: 1 First name: admin</pre>")
_NO_ROW = _LAYOUT.format("<pre>ID: 1 </pre>")


def _is_false_payload(value: str) -> bool:
    """
    Args:
        value (str): The injected value.

    Returns:
        bool: Whether the value carries one of the always-false boolean payloads.
    """
    return "1=2" in value or "'1'='2" in value


def _row_lookup(*, reproduces: bool = True) -> _Render:
    """
    Args:
        reproduces (bool): ``False`` makes the FALSE payload answer 404 only the first time.

    Returns:
        _Render: A lookup keyed on the id: a value starting with ``1`` matches a row (200),
            any other value matches none (404), and an always-false payload cancels the match.
    """
    false_seen = {"n": 0}

    def render(value: str) -> Response:
        matches = value.startswith("1")
        if matches and _is_false_payload(value):
            false_seen["n"] += 1
            matches = not reproduces and false_seen["n"] > 1
        if matches:
            return _resp(_ROW)
        return _resp(_NO_ROW, status=404)

    return render


def test_the_seed_is_a_digit_for_an_id_name_and_a_letter_otherwise() -> None:
    """Id-looking names get a digit, everything else a single letter."""
    for name in ("id", "user_id", "userId", "item_num", "orderNumber"):
        point = InjectionPoint("GET", "https://example.com/i", name, "", ((name, ""),))
        assert sqli._seed_for(point) == "1", name
    for name in ("q", "search", "name", "txtName"):
        point = InjectionPoint("GET", "https://example.com/i", name, "", ((name, ""),))
        assert sqli._seed_for(point) == "a", name


async def test_boolean_based_finds_a_field_that_ships_empty() -> None:
    """An empty default matches no row, so the pairs run on a seed and the status splits them."""
    hits = await sqli.detect_boolean(
        _EMPTY_POINT, _baseline(_NO_ROW, status=404), _ctx(_row_lookup())
    )
    assert len(hits) == 1 and hits[0].kind == "sqli-boolean"
    assert hits[0].payload == "1' AND '1'='1"
    evidence = dict(hits[0].evidence)
    assert evidence["Seeded value"].startswith("'1'")
    assert evidence["Status"] == "TRUE 200 vs FALSE 404 (baseline 200)"


async def test_boolean_based_status_split_is_medium_confidence() -> None:
    """Two pages that differ only by status class are a thinner signal than pages that differ."""
    (hit,) = await sqli.detect_boolean(
        _EMPTY_POINT, _baseline(_NO_ROW, status=404), _ctx(_row_lookup())
    )
    assert hit.confidence.name == "MEDIUM"


async def test_boolean_based_status_split_on_a_field_with_a_default() -> None:
    """A field with a value needs no seed: TRUE is the baseline's page, FALSE is a 404."""
    (hit,) = await sqli.detect_boolean(_POINT, _baseline(_ROW), _ctx(_row_lookup()))
    assert "Seeded value" not in dict(hit.evidence)
    assert "Status" in dict(hit.evidence)


async def test_boolean_based_a_body_split_is_still_high_confidence() -> None:
    """The original rule is untouched: pages that differ in content stay HIGH."""
    body = "<div>Widget A</div><div>Widget B</div>"
    (hit,) = await sqli.detect_boolean(
        _POINT, _baseline(body), _ctx(_boolean_render(body, "<div>No results</div>"))
    )
    assert hit.confidence.name == "HIGH"
    assert "Status" not in dict(hit.evidence)


async def test_boolean_based_status_split_that_does_not_reproduce_is_rejected() -> None:
    """A FALSE payload that answers 404 once and 200 the next time is noise."""
    hits = await sqli.detect_boolean(_POINT, _baseline(_ROW), _ctx(_row_lookup(reproduces=False)))
    assert hits == []


async def test_boolean_based_status_split_needs_the_true_page_to_track_the_baseline() -> None:
    """TRUE answering in another class than the baseline is not the boolean shape."""

    def render(value: str) -> Response:
        if _is_false_payload(value) or value == "1":
            return _resp(_ROW)
        return _resp(_NO_ROW, status=404)

    assert await sqli.detect_boolean(_POINT, _baseline(_ROW), _ctx(render)) == []


async def test_boolean_based_unstable_status_is_rejected() -> None:
    """If the unpayloaded request does not keep the baseline's status, the split is noise."""

    def render(value: str) -> Response:
        if value == "1":
            return _resp(_ROW, status=500)
        if _is_false_payload(value):
            return _resp(_NO_ROW, status=404)
        return _resp(_ROW)

    assert await sqli.detect_boolean(_POINT, _baseline(_ROW), _ctx(render)) == []


async def test_boolean_based_empty_field_where_the_seed_changes_nothing_stops_early() -> None:
    """When the seed leaves the page as the empty value had it, only the seed is spent."""
    sent: list[str] = []

    def render(value: str) -> Response:
        sent.append(value)
        return _resp(_NO_ROW, status=404)

    hits = await sqli.detect_boolean(_EMPTY_POINT, _baseline(_NO_ROW, status=404), _ctx(render))
    assert hits == []
    assert sent.count("1") == 1  # the seed for an "id" field, sent once
    assert not any(v.startswith("1") and len(v) > 1 for v in sent)


async def test_boolean_based_empty_field_with_a_seed_that_changes_the_page_but_no_split() -> None:
    """A search box that lists results for the seed, whatever follows it, is not injectable."""

    def render(value: str) -> Response:
        return _resp(_NO_ROW if not value else _ROW)

    hits = await sqli.detect_boolean(_EMPTY_POINT, _baseline(_NO_ROW), _ctx(render))
    assert hits == []


async def test_boolean_based_a_denied_seed_request_gives_no_hit() -> None:
    """If the budget refuses the seed, the detector stops without a verdict."""

    def render(value: str) -> Response | None:
        return None if value == "1" else _resp(_NO_ROW, status=404)

    hits = await sqli.detect_boolean(_EMPTY_POINT, _baseline(_NO_ROW, status=404), _ctx(render))
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
