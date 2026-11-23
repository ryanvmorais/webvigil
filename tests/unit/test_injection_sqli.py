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

import httpx2

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx, normalize_body, sqli
from webvigil.checks.injection.detect._diff import ratio
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
        headers=httpx2.Headers({"content-type": "text/html"}),
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
    """
    A target whose response time grows one second per requested sleep-second.

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


# ---------------------------------------------------------------------------
# Requests refused by the budget, thresholds on their exact values
# ---------------------------------------------------------------------------


def _recording(render: _Render, seen: list[str], deny_at: int = 0, **kwargs: int) -> DetectCtx:
    """
    Args:
        render (_Render): The target.
        seen (list[str]): Every value sent is appended to it.
        deny_at (int): The 1-based request that ``send`` refuses (``None``); 0 refuses none.
        **kwargs (int): Passed to ``_ctx`` (``delay_s``).

    Returns:
        DetectCtx: A context that records the values and refuses one request.
    """
    return _ctx(lambda v: None if seen.append(v) or len(seen) == deny_at else render(v), **kwargs)


# quick_ratio counts the characters two bodies share: 90 of 100 on each side is exactly 0.90.
_PAGE = "." * 90 + "," * 10
_AT_GAP = "." * 90 + ";" * 10
_PAST_GAP = "." * 89 + ";" * 11
_OTHER = "#" * 100


def test_the_threshold_pages_sit_where_the_tests_say() -> None:
    """The bodies below are built on the 0.90 page-stability ceiling."""
    assert ratio(_PAGE, _AT_GAP) == 0.90
    assert ratio(_PAGE, _PAST_GAP) == 0.89
    assert ratio(_PAGE, _OTHER) == 0.0


async def test_error_based_a_denied_probe_stops_the_detector() -> None:
    """A ``None`` on a later probe ends the loop: nothing is sent after it."""
    seen: list[str] = []
    ctx = _recording(lambda v: _resp("<div>Widget</div>"), seen, deny_at=2)
    assert await sqli.detect_error(_POINT, _baseline(), ctx) == []
    assert seen == ["1" + p for p in payloads.SQLI_ERROR[:2]]


async def test_error_based_evidence_quotes_the_database_error() -> None:
    """The matched error text is the evidence, not an empty string."""
    error = "ORA-01756: quoted string not properly terminated"
    (hit,) = await sqli.detect_error(_POINT, _baseline(), _ctx(lambda v: _resp(f"<p>{error}</p>")))
    assert dict(hit.evidence)["Database error"] == "ORA-01756"


def _split_page(value: str) -> Response:
    """
    Args:
        value (str): The injected value.

    Returns:
        Response: ``_PAGE`` for the baseline and TRUE, ``_OTHER`` for FALSE.
    """
    return _resp(_OTHER if _is_false_payload(value) else _PAGE)


async def test_boolean_based_a_denied_request_at_each_stage_stops_the_detector() -> None:
    """Either side of a pair, the restatement, either side of the repeat: nothing after it."""
    for deny_at, sent in ((1, 2), (2, 2), (3, 3), (4, 5), (5, 5)):  # a pair goes out together
        seen: list[str] = []
        ctx = _recording(_split_page, seen, deny_at)
        assert await sqli.detect_boolean(_POINT, _baseline(_PAGE), ctx) == [], deny_at
        assert len(seen) == sent, deny_at
    seen = []
    assert await sqli.detect_boolean(_POINT, _baseline(_PAGE), _recording(_split_page, seen))
    assert len(seen) == 5  # control: the same target, no refusal, is a hit


async def test_boolean_based_a_page_with_no_split_sends_each_pair_once() -> None:
    """No restatement or repeat without a split, and no seed for a field that has a value."""
    seen: list[str] = []
    flat = _recording(lambda v: _resp(_PAGE), seen)
    assert await sqli.detect_boolean(_POINT, _baseline(_PAGE), flat) == []
    assert seen == ["1" + p for pair in payloads.SQLI_BOOLEAN_PAIRS for p in pair]


async def test_boolean_based_an_empty_field_that_already_splits_needs_no_seed() -> None:
    """The pairs on the empty value find the split; the seed is never sent."""
    seen: list[str] = []
    (hit,) = await sqli.detect_boolean(
        _EMPTY_POINT, _baseline(_PAGE), _recording(_split_page, seen)
    )
    assert hit.payload == payloads.SQLI_BOOLEAN_PAIRS[0][0]
    assert "Seeded value" not in dict(hit.evidence)
    assert "1" not in seen


async def test_boolean_based_the_restatement_may_sit_on_the_ceiling() -> None:
    """A restated page exactly 0.90 alike is stable; 0.89 is noise."""
    for restated, hit in ((_AT_GAP, True), (_PAST_GAP, False)):

        def render(value: str, again: str = restated) -> Response:
            return _resp(again) if value == "1" else _split_page(value)

        hits = await sqli.detect_boolean(_POINT, _baseline(_PAGE), _ctx(render))
        assert bool(hits) is hit, restated


async def test_boolean_based_a_seed_on_the_ceiling_changed_nothing() -> None:
    """A seeded page 0.90 alike is the same page: no pairs on it; 0.89 is a new page."""
    for seeded, hit in ((_AT_GAP, False), (_PAST_GAP, True)):

        def render(value: str, page: str = seeded) -> Response:
            if value == "":
                return _resp(_PAGE)
            return _resp(_OTHER if _is_false_payload(value) else page)

        hits = await sqli.detect_boolean(_EMPTY_POINT, _baseline(_PAGE), _ctx(render))
        assert bool(hits) is hit, seeded


async def test_boolean_based_a_seed_that_only_changes_the_body_runs_the_pairs() -> None:
    """Same status, another page: the seed matched rows, so the pairs run on it."""

    def render(value: str) -> Response:
        if value == "" or _is_false_payload(value):
            return _resp("<p>no results</p>")
        return _resp("<ul><li>apple</li><li>banana</li><li>cherry</li></ul>")

    q = InjectionPoint("GET", "https://example.com/search", "q", "", (("q", ""),))
    (hit,) = await sqli.detect_boolean(q, _baseline("<p>no results</p>"), _ctx(render))
    assert dict(hit.evidence)["Seeded value"].startswith("'a'")
    assert hit.confidence.name == "HIGH"


def _timed(control_ms: float, slow_ms: float, half_ms: float) -> _Render:
    """
    Args:
        control_ms (float): The answer time to a zero-second sleep.
        slow_ms (float): The answer time to the full five-second delay.
        half_ms (float): The answer time to the two-second confirmation.

    Returns:
        _Render: A target that answers each kind of time payload in a fixed time.
    """

    def render(value: str) -> Response:
        match = re.search(r"(?:SLEEP|pg_sleep)\((\d+)\)|DELAY '0:0:(\d+)'", value)
        seconds = int(match.group(1) or match.group(2)) if match else 0
        elapsed = {0: control_ms, 5: slow_ms, 2: half_ms}[seconds]
        return _resp("<div>Widget</div>", elapsed_ms=elapsed)

    return render


async def test_time_based_the_delay_threshold_is_inclusive() -> None:
    """``delay - 1`` seconds over the floor is slow enough; one millisecond less is not."""
    hits = await sqli.detect_time(_POINT, _baseline(), _ctx(_timed(100, 4100, 2100)))
    assert len(hits) == 1
    assert await sqli.detect_time(_POINT, _baseline(), _ctx(_timed(100, 4099, 2100))) == []


async def test_time_based_the_confirmation_band_is_inclusive() -> None:
    """At half = 2 s the confirmation lands 1 to 4 s over the floor, both ends included."""
    for half_ms, hit in ((1100, True), (1099, False), (4100, True), (4101, False)):
        hits = await sqli.detect_time(_POINT, _baseline(), _ctx(_timed(100, 5100, half_ms)))
        assert bool(hits) is hit, half_ms


async def test_time_based_a_slow_control_or_baseline_raises_the_floor() -> None:
    """The floor is the slower of the control and the baseline, so neither alone can hide it."""
    slow_control = _timed(control_ms=4500, slow_ms=5000, half_ms=3000)
    assert await sqli.detect_time(_POINT, _baseline(), _ctx(slow_control)) == []
    fast_control = _timed(control_ms=10, slow_ms=5000, half_ms=3000)
    assert await sqli.detect_time(_POINT, _baseline(elapsed_ms=4500), _ctx(fast_control)) == []
    assert await sqli.detect_time(_POINT, _baseline(), _ctx(fast_control))  # control


async def test_time_based_a_target_that_never_slows_costs_two_requests_per_dbms() -> None:
    """No confirmation without a slow answer."""
    seen: list[str] = []
    flat = _recording(lambda v: _resp("<div>Widget</div>", elapsed_ms=100.0), seen)
    assert await sqli.detect_time(_POINT, _baseline(), flat) == []
    assert len(seen) == 2 * len(payloads.SQLI_TIME)


async def test_time_based_a_denied_control_or_delay_stops_the_detector() -> None:
    """A ``None`` on the control or the delayed request ends the detector."""

    def flat(value: str) -> Response:
        return _resp("<div>Widget</div>", elapsed_ms=100.0)

    for deny_at in (1, 2, 3, 4):
        seen: list[str] = []
        assert await sqli.detect_time(_POINT, _baseline(), _recording(flat, seen, deny_at)) == []
        assert len(seen) == deny_at, deny_at


async def test_time_based_a_denied_confirmation_is_medium_confidence() -> None:
    """The delay is seen but its half-delay repeat is refused: a thinner hit."""
    (hit,) = await sqli.detect_time(_POINT, _baseline(), _recording(_time_render, [], deny_at=3))
    assert hit.confidence.name == "MEDIUM"


async def test_time_based_a_one_second_delay_confirms_at_one_second() -> None:
    """Half of one second rounds up to one, never to a zero-second sleep."""
    seen: list[str] = []
    (hit,) = await sqli.detect_time(_POINT, _baseline(), _recording(_time_render, seen, delay_s=1))
    assert seen == ["1' AND SLEEP(0)-- -", "1' AND SLEEP(1)-- -", "1' AND SLEEP(1)-- -"]
    assert hit.confidence.name == "HIGH"
