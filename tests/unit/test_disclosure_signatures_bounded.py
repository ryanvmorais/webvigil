"""
The error-page signatures cost time proportional to the size of a body, and still match real pages.

The text the signatures read comes from the scanned site, so a pattern whose matching time grows
faster than the body would let a hostile site stall a scan. Nothing is mocked: each test hands
:func:`~webvigil.checks.disclosure.signatures.match_error` a real string and reads the verdict or
the clock. The time limit is far above what the bounded patterns need (tens of milliseconds) and
far below what the unbounded ones needed on the same input, so a slow CI runner cannot fail it and
a regression to an unbounded pattern cannot pass it.
"""

from __future__ import annotations

import time

import pytest

from webvigil.checks.disclosure.signatures import _SCAN_MAX, is_directory_listing, match_error

# Seconds a single body may take. The bounded patterns finish these inputs in well under a second.
_BUDGET_S = 5.0


def _elapsed(body: str) -> float:
    """
    Args:
        body (str): A response body.

    Returns:
        float: Seconds :func:`match_error` took on it.
    """
    started = time.perf_counter()
    match_error(body)
    return time.perf_counter() - started


# ---------------------------------------------------------------------------
# Cost: long inputs of repeated pieces finish quickly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("Error: x" + " " * 4000 + "y", id="node-long-gap"),
        pytest.param(
            "Traceback (most recent call last):" + " " * 20000 + "z", id="python-long-gap"
        ),
        pytest.param("a." * 28, id="java-dotted-name"),
        pytest.param("org.example.FooException: " + "x " * 3000, id="java-long-message"),
        pytest.param("a" * 100_000, id="one-long-word"),
        pytest.param("<code>" + "a" * 290 + "</code>" * 50, id="rails-code-tags"),
        pytest.param('<div id="summary">' + " " * 150 + "<h1>" + "a" * 190 + "</h1>", id="django"),
    ],
)
def test_a_long_body_of_repeated_pieces_is_scanned_quickly(body: str) -> None:
    """The gap, dotted-name and long-word shapes used to take far longer; all fit the budget now."""
    assert _elapsed(body) < _BUDGET_S


def test_only_the_first_scan_max_characters_are_read() -> None:
    """A marker past the cap is not read; the same marker just inside it still fires."""
    marker = "Werkzeug Debugger"
    padding = "." * (_SCAN_MAX - len(marker))
    assert match_error(padding + marker) is not None
    assert match_error(padding + " " + marker) is None


def test_the_cap_applies_to_directory_listings_too() -> None:
    """The listing signatures read the same bounded prefix."""
    marker = "<title>Index of /"
    padding = "." * (_SCAN_MAX - len(marker))
    assert is_directory_listing(padding + marker)
    assert not is_directory_listing(padding + " " + marker)


# ---------------------------------------------------------------------------
# Behaviour: real pages are still recognised
# ---------------------------------------------------------------------------


def test_java_trace_with_a_nested_class_and_html_gaps_matches() -> None:
    """A nested class name, a message and ``<br />`` / ``&nbsp;`` gaps before the frame."""
    body = (
        "<pre>com.example.Outer.InnerException: boom<br />&nbsp;&nbsp;&nbsp;&nbsp;"
        "at com.example.Outer.run(Outer.java:12)</pre>"
    )
    hit = match_error(body)
    assert hit is not None
    assert hit.signature.framework == "Java"


def test_java_trace_without_a_message_matches() -> None:
    """The message after the class name is optional."""
    body = "java.lang.NullPointerException\n\tat com.example.Service.call(Service.java:42)"
    hit = match_error(body)
    assert hit is not None
    assert hit.signature.framework == "Java"


@pytest.mark.parametrize(
    "frame",
    [
        "at handler (/app/index.js:3:9)",
        "at handler (/app/index.js:3)",
    ],
    ids=["line-and-column", "line-only"],
)
def test_node_trace_matches_with_and_without_a_column(frame: str) -> None:
    """A frame ends in ``file:line`` or ``file:line:column``."""
    hit = match_error(f"TypeError: x is not a function<br>    {frame}")
    assert hit is not None
    assert hit.signature.framework == "Node.js"


def test_python_traceback_with_escaped_quotes_matches() -> None:
    """An HTML-escaped first frame (``File &quot;...``) after ``<br>`` and ``&nbsp;`` gaps."""
    body = (
        "Traceback (most recent call last):<br>&nbsp;&nbsp;File &quot;/app/views.py&quot;, line 3"
    )
    hit = match_error(body)
    assert hit is not None
    assert hit.signature.framework == "Python"


def test_django_and_rails_chrome_still_match() -> None:
    """The two patterns that lost an unbounded ``.+`` still recognise their pages."""
    django = '<div id="summary">\n  <h1>OperationalError at /accounts/</h1>'
    rails = "<code>/app/app/controllers/users_controller.rb</code>"
    assert match_error(django) is not None
    assert match_error(rails) is not None
