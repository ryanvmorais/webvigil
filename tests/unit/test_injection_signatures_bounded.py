"""
The injection signatures and the body normaliser cost time proportional to a body's size.

The response to an injected request comes from the scanned site, so a pattern whose matching time
grows faster than the body would let a hostile site stall an Active Mode scan. Nothing is mocked:
each test hands a real pattern a real string and reads the verdict or the clock. The time limit is
far above what the bounded patterns need (milliseconds) and far below what the unbounded ones
needed on the same input, so a slow CI runner cannot fail it and a regression to an unbounded
pattern cannot pass it.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable

import pytest

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import normalize_body

# Seconds a single body may take. The bounded patterns finish these inputs in well under a second.
_BUDGET_S = 5.0
# Characters of a body in the cost tests: below the cap the detectors read, above what an
# unbounded pattern could scan in the budget.
_SIZE = 200_000


def _mysql() -> re.Pattern[str]:
    """
    Returns:
        re.Pattern[str]: The MySQL error signature.
    """
    return dict(payloads.SQL_ERROR_SIGNATURES)["MySQL"]


def _sqlite() -> re.Pattern[str]:
    """
    Returns:
        re.Pattern[str]: The SQLite error signature.
    """
    return dict(payloads.SQL_ERROR_SIGNATURES)["SQLite"]


def _handlebars() -> re.Pattern[str]:
    """
    Returns:
        re.Pattern[str]: The Handlebars template-error signature.
    """
    return dict(payloads.SSTI_ERROR_SIGNATURES)["Handlebars"]


# ---------------------------------------------------------------------------
# Cost: long inputs of repeated pieces finish quickly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("make_pattern", "piece"),
    [
        pytest.param(_mysql, "SQL syntax", id="mysql"),
        pytest.param(_sqlite, 'near "', id="sqlite"),
        pytest.param(_handlebars, "hbs", id="handlebars"),
    ],
)
def test_an_error_signature_reads_a_long_repeated_body_quickly(
    make_pattern: Callable[[], re.Pattern[str]], piece: str
) -> None:
    """The signatures that ran across a whole line now stop within a bounded distance."""
    pattern = make_pattern()
    body = piece * (_SIZE // len(piece))
    started = time.perf_counter()
    pattern.search(body)
    assert time.perf_counter() - started < _BUDGET_S


def test_the_passwd_signature_reads_a_long_repeated_body_quickly() -> None:
    """The traversal signature gives up on a line after a bounded distance."""
    body = "root:" * (_SIZE // 5)
    started = time.perf_counter()
    for pattern in payloads.TRAVERSAL_SIGNATURES:
        pattern.search(body)
    assert time.perf_counter() - started < _BUDGET_S


def test_the_hidden_input_normaliser_reads_a_long_repeated_body_quickly() -> None:
    """Tags that never close are scanned once each, up to the next angle bracket."""
    started = time.perf_counter()
    normalize_body("<input " * (_SIZE // 7))
    assert time.perf_counter() - started < _BUDGET_S


# ---------------------------------------------------------------------------
# The cap on what the detectors read
# ---------------------------------------------------------------------------


def test_head_keeps_the_first_scan_max_characters() -> None:
    """:func:`~webvigil.checks.injection.payloads.head` cuts a body at ``SCAN_MAX``."""
    body = "a" * (payloads.SCAN_MAX + 10)
    assert payloads.head(body) == "a" * payloads.SCAN_MAX
    assert payloads.head("short") == "short"


def test_a_signature_past_the_cap_is_not_read() -> None:
    """A marker just inside the cap is found; the same marker one character later is not."""
    marker = "PSQLException"
    padding = "." * (payloads.SCAN_MAX - len(marker))
    postgres = dict(payloads.SQL_ERROR_SIGNATURES)["PostgreSQL"]
    assert postgres.search(payloads.head(padding + marker))
    assert not postgres.search(payloads.head(padding + " " + marker))


# ---------------------------------------------------------------------------
# Behaviour: real error pages are still recognised
# ---------------------------------------------------------------------------


def test_the_mysql_message_still_matches() -> None:
    """The text MySQL puts in a syntax error."""
    body = "You have an error in your SQL syntax; check the manual for your MySQL server version"
    assert _mysql().search(body)


def test_the_sqlite_message_still_matches() -> None:
    """The text SQLite puts in a syntax error."""
    assert _sqlite().search('near "x": syntax error')


def test_the_handlebars_message_still_matches() -> None:
    """Both spellings of a Handlebars parse error."""
    assert _handlebars().search("Handlebars: Parse error on line 1")
    assert _handlebars().search("hbs template: Parse error on line 2")


def test_a_passwd_line_still_matches() -> None:
    """The first line of ``/etc/passwd``."""
    hit = payloads.TRAVERSAL_SIGNATURES[0].search("root:x:0:0:root:/root:/bin/bash")
    assert hit is not None


def test_a_hidden_input_is_dropped_and_a_visible_one_is_kept() -> None:
    """The normaliser removes hidden inputs in any attribute order and leaves the rest."""
    body = (
        '<input name="t" value="abc" type="hidden"><input type="text" name="q"><input TYPE=hidden>'
    )
    assert normalize_body(body) == '<input type="text" name="q">'
