"""
The searches of spec 027 (RF-03, RF-04, RF-05): each finds what it is meant to find.

A search that could never match would let every run pass, so each one is shown matching a value
planted in each form it claims to cover, and staying quiet on an output that does not hold it.
"""

from __future__ import annotations

import base64
import html
import json
from urllib.parse import quote, quote_plus

from tests.failure.outputs import (
    STORED,
    Outputs,
    bad_failure_hits,
    bound_of,
    credential_hits,
    failure_hits,
    family,
)
from tests.failure.table import PAD_CHAR, Kind, credential_marker, failure_marker, failure_text
from tests.support import spellings
from webvigil.core.bounded import TEXT_MAX_CHARS
from webvigil.core.output import TERMINAL_MAX_CHARS, Sink, safe_text

# Every form differs: the slash, space and plus, the quotes and markup, a non-ASCII letter, and an
# ending whose base64 holds the two characters the alphabets disagree on.
_VALUE = "wv-cred-test/a b+c&d<e>'\"é~?>"


def test_spellings_cover_the_eight_forms() -> None:
    """As typed, both percent-encodings, JSON, HTML, ``repr`` and both base64 alphabets."""
    raw = _VALUE.encode("utf-8")
    expected = {
        _VALUE,
        quote(_VALUE, safe=""),
        quote_plus(_VALUE),
        json.dumps(_VALUE)[1:-1],
        html.escape(_VALUE),
        repr(_VALUE)[1:-1],
        base64.b64encode(raw).decode("ascii"),
        base64.urlsafe_b64encode(raw).decode("ascii"),
    }
    assert spellings(_VALUE) == expected
    assert len(expected) == 8  # the value was chosen so that no two forms coincide


def test_a_credential_is_found_in_every_spelling_and_nowhere_else() -> None:
    """Each form planted in its own output is a hit naming that output; a clean output is not."""
    marker = credential_marker("cookie")
    outputs = Outputs()
    for n, form in enumerate(sorted(spellings(marker))):
        outputs.add(f"report:{n}", f"before {form} after")
    outputs.add("stdout", "nothing here: wv-cred-cookie- alone is not the marker")
    hits = credential_hits(outputs, [marker])
    assert {hit.output for hit in hits} == {f"report:{n}" for n in range(len(spellings(marker)))}
    assert all(hit.marker == marker for hit in hits)


def test_a_failure_is_allowed_only_where_its_kind_may_go() -> None:
    """
    A server error's body may be quoted in a report, never on the terminal; a database error only
    in the server log; any other kind nowhere.
    """
    server = failure_marker("crawl", Kind.SERVER_ERROR)
    db = failure_marker("api-store", Kind.DB)
    reset = failure_marker("crawl", Kind.RESET)
    outputs = Outputs()
    outputs.add("report:json", f"evidence {server}")
    outputs.add("stderr", f"error {server}")
    outputs.add("server-log", f"failed {db}")
    outputs.add("log", f"warning {reset}")
    markers = {server: Kind.SERVER_ERROR, db: Kind.DB, reset: Kind.RESET}
    verdicts = {(hit.output, hit.marker): hit.allowed for hit in failure_hits(outputs, markers)}
    assert verdicts == {
        ("report:json", server): True,
        ("stderr", server): False,
        ("server-log", db): True,
        ("log", reset): False,
    }


def test_an_allowed_hit_must_be_bounded_and_neutralized() -> None:
    """The raw hostile text is two problems; the same text through ``safe_text`` is none."""
    marker = failure_marker("crawl", Kind.SERVER_ERROR)
    raw = failure_text(marker)
    outputs = Outputs()
    outputs.add("report:json", raw)
    (hit,) = bad_failure_hits(outputs, {marker: Kind.SERVER_ERROR})
    assert any(problem.startswith("raw ") for problem in hit.problems)
    assert any("past" in problem for problem in hit.problems)

    treated = Outputs()
    treated.add("report:md", safe_text(raw, Sink.LOG, one_line=True))
    assert bad_failure_hits(treated, {marker: Kind.SERVER_ERROR}) == []
    assert failure_hits(treated, {marker: Kind.SERVER_ERROR})  # still found, so it was searched


def test_the_bound_is_the_terminals_on_the_streams() -> None:
    """A padding run that fits ``Text`` is still too long for the terminal."""
    assert bound_of("stderr") == bound_of("stdout:report") == TERMINAL_MAX_CHARS
    assert bound_of("report:html") == bound_of("log") == TEXT_MAX_CHARS
    marker = failure_marker("crawl", Kind.SERVER_ERROR)
    outputs = Outputs()
    outputs.add("report:json", marker + PAD_CHAR * (TERMINAL_MAX_CHARS + 1))
    assert bad_failure_hits(outputs, {marker: Kind.SERVER_ERROR}) == []
    outputs = Outputs()
    outputs.add("stdout", marker + PAD_CHAR * (TERMINAL_MAX_CHARS + 1))
    assert bad_failure_hits(outputs, {marker: Kind.SERVER_ERROR})


def test_a_numbered_output_keeps_its_family() -> None:
    """The second record of the server log may hold a database error as the first may."""
    db = failure_marker("api-store", Kind.DB)
    outputs = Outputs()
    for _ in range(2):
        outputs.add("server-log", f"failed {db}")
    assert [hit.allowed for hit in failure_hits(outputs, {db: Kind.DB})] == [True, True]
    assert family("stderr#2") == family("stderr:report#3") == "stderr"
    assert bound_of("stderr#2") == TERMINAL_MAX_CHARS


def test_a_stored_value_is_checked_for_its_bound_only() -> None:
    """
    The database and the API's JSON hold a value as it was stored, bounded, and the dashboard
    neutralizes it where it shows it: raw controls pass there and a run past the bound does not.
    The same stored text in a report is a problem.
    """
    marker = failure_marker("checks", Kind.SERVER_ERROR)
    markers = {marker: Kind.SERVER_ERROR}
    stored = safe_text(failure_text(marker), Sink.STORE)
    outputs = Outputs()
    for name in sorted(STORED):
        outputs.add(f"{name}:row", stored)
    assert bad_failure_hits(outputs, markers) == []
    assert len(failure_hits(outputs, markers)) == len(STORED)  # found, so it was searched

    unbounded = Outputs()
    unbounded.add("db:finding", failure_text(marker))
    (hit,) = bad_failure_hits(unbounded, markers)
    assert len(hit.problems) == 1 and "past" in hit.problems[0]

    report = Outputs()
    report.add("report:html", stored)
    (hit,) = bad_failure_hits(report, markers)
    assert any(problem.startswith("raw ") for problem in hit.problems)


def test_outputs_of_the_same_name_are_numbered() -> None:
    """A second output of one name is kept beside the first, not over it."""
    outputs = Outputs()
    for text in ("a", "b", "c"):
        outputs.add("log", text)
    assert outputs.texts == {"log": "a", "log#2": "b", "log#3": "c"}
