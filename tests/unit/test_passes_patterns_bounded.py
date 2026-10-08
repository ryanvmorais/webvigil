"""
The envelope and CSRF-confirmation patterns cost time proportional to a response's size.

Both Active Mode passes read text the scanned site controls: the envelope pass reads the answer
to a poisoned ``Host`` header and the echo of a ``TRACE`` request, and the CSRF pass reads the
answer to a replayed form. A pattern whose time grows faster than the text would let a hostile
site stall the scan. Nothing is mocked: each test hands a real pattern a real string and reads the
verdict or the clock. The time limit is far above what the bounded patterns need and far below what
the unbounded ones needed on the same input.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import pytest

from webvigil.checks.csrf.scanner import _REJECTION_RE
from webvigil.checks.envelope.scanner import (
    _BASE_CANON,
    _SCAN_MAX,
    _SECRET_HEADER_LINE,
    _SENTINEL_IN_URL,
)

# Seconds a single body may take. The bounded patterns finish these inputs in well under a second.
_BUDGET_S = 5.0
# Characters of a body in the cost tests: what the passes read, and more than an unbounded pattern
# could scan in the budget.
_SIZE = 200_000


def _seconds(action: Callable[[], object]) -> float:
    """
    Args:
        action (Callable[[], object]): A zero-argument callable.

    Returns:
        float: Seconds it took to run.
    """
    started = time.perf_counter()
    action()
    return time.perf_counter() - started


# ---------------------------------------------------------------------------
# Cost: long inputs of repeated pieces finish quickly
# ---------------------------------------------------------------------------


def test_the_trace_echo_redaction_reads_a_run_of_blank_lines_quickly() -> None:
    """A header line starts with spaces or tabs, so a run of line breaks is not one long indent."""
    body = "\n" * _SIZE
    assert _seconds(lambda: _SECRET_HEADER_LINE.sub("x", body)) < _BUDGET_S


@pytest.mark.parametrize(
    "piece",
    [
        pytest.param("<base ", id="base-tags"),
        pytest.param('rel="canonical" ', id="canonical-links"),
        pytest.param("property='og:url' ", id="og-url"),
    ],
)
def test_the_base_and_canonical_pattern_reads_repeated_tags_quickly(piece: str) -> None:
    """A tag ends at the next angle bracket, so each start reads only its own tag."""
    body = piece * (_SIZE // len(piece))
    assert _seconds(lambda: _BASE_CANON.search(body)) < _BUDGET_S


def test_the_body_url_pattern_reads_a_run_of_schemes_quickly() -> None:
    """A URL is looked for within a bounded distance of its scheme."""
    body = "http://" * (_SIZE // 7)
    assert _seconds(lambda: _SENTINEL_IN_URL.search(body)) < _BUDGET_S


def test_the_rejection_words_read_a_run_of_one_word_quickly() -> None:
    """A word that begins a rejection phrase is followed for a bounded distance."""
    body = "mismatch" * (_SIZE // 8)
    assert _seconds(lambda: _REJECTION_RE.search(body)) < _BUDGET_S


# ---------------------------------------------------------------------------
# Behaviour: real pages are still recognised
# ---------------------------------------------------------------------------


def test_the_cap_is_the_one_the_signatures_use() -> None:
    """The envelope pass reads the same 256 KiB head as the error-page signatures."""
    assert _SCAN_MAX == 256 * 1024


def test_the_echo_redaction_masks_credential_lines_and_keeps_the_rest() -> None:
    """Header lines with credentials are masked, with an indent or without."""
    echo = "TRACE / HTTP/1.1\nHost: example.com\n  Cookie: sid=1\nAuthorization: Bearer x\n"
    masked = _SECRET_HEADER_LINE.sub(r"\1: ***redacted***", echo)
    assert "sid=1" not in masked
    assert "Bearer x" not in masked
    assert "Host: example.com" in masked


@pytest.mark.parametrize(
    "markup",
    [
        '<base href="https://webvigil.invalid/">',
        '<link rel="canonical" href="https://webvigil.invalid/page">',
        '<meta property="og:url" content="https://webvigil.invalid/page">',
    ],
)
def test_a_poisoned_base_or_canonical_url_is_still_found(markup: str) -> None:
    """The three tags that carry the reflected host."""
    assert _BASE_CANON.search(markup)


def test_a_reflected_url_in_the_body_is_still_found() -> None:
    """A link to the sentinel host with a path and a query."""
    assert _SENTINEL_IN_URL.search('<a href="https://webvigil.invalid/reset?t=1">')


@pytest.mark.parametrize(
    "text",
    [
        "Invalid CSRF token",
        "The token is missing from your request",
        "Your session has expired",
        "origin mismatch detected",
        "403 Forbidden",
    ],
)
def test_a_rejection_page_is_still_recognised(text: str) -> None:
    """The phrases a framework puts on a rejected form."""
    assert _REJECTION_RE.search(text)


def test_an_ordinary_page_is_not_a_rejection() -> None:
    """Plain prose does not read as a rejection."""
    assert not _REJECTION_RE.search("Your profile has been saved. Thanks for the update.")
