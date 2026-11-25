"""
The safe-output module — spec 025, RF-01, RF-02, RF-04, RF-11.

Every function under test is pure, except the log filter, which is attached to a logger named for
the test and removed afterwards, and observed through ``caplog`` at ``DEBUG``. The cut rule is
driven by a secret whose spellings differ (a quote, a space, ``&``, ``/``, ``<`` and a non-ASCII
letter), placed so that each cut splits it at every offset; the filler is ``~``, which no
spelling holds, so any four characters of a spelling left in the output are a fragment of it.
Nothing touches the network.
"""

from __future__ import annotations

import logging
import re
import traceback
from collections.abc import Callable, Iterator

import pytest
from pydantic import TypeAdapter

from webvigil.checks.envelope.scanner import _SENTINEL, EnvelopeScanner
from webvigil.checks.injection.detect import cmdi, ssrf, xss
from webvigil.checks.upload import scanner as upload
from webvigil.core.bounded import (
    EVIDENCE_MARKER,
    NAME_MAX_CHARS,
    TEXT_MAX_CHARS,
    TRUNCATION_MARKER,
    URL_MAX_CHARS,
    Name,
    Text,
    Url,
    store_text,
)
from webvigil.core.findings import EvidenceItem
from webvigil.core.output import (
    CUT_MARKERS,
    MIN_SECRET_LENGTH,
    REDACTED,
    TERMINAL_MAX_CHARS,
    Redactor,
    SafeLogFilter,
    Sink,
    _spellings,
    get_logger,
    safe_text,
    safe_traceback,
)
from webvigil.core.text import escape_json_controls, show_controls

# Every character the neutralization escapes, line breaks and tabs included.
_RAW_ANY = re.compile(
    r"[\x00-\x09\x0b-\x1f\x7f-\x9f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
)
# The same, with tab and line feed allowed: what a multi-line profile may leave.
_RAW_MULTI_LINE = re.compile(
    r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
)
# What the JSON profile escapes; the C0 controls are the JSON encoder's.
_RAW_JSON = re.compile(
    r"[\x7f-\x9f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
)
# ESC, a C1 control, a tab, a line feed, a CRLF, a bidirectional override, a zero-width space and
# an unpaired surrogate.
_HOSTILE = "a\x1b[2Jb\x85c\td\ne\r\nf\u202eg\u200bh\ud800i"
_OVERSIZED = _HOSTILE + "y" * (2 * URL_MAX_CHARS)

_SECRET = 'Wv"9 s&k/é<t'
_SPELLINGS = sorted(_spellings(_SECRET), key=len)
_FILL = "~"


def _fragment_left(text: str, spelling: str) -> bool:
    """
    Tell whether any fragment of a spelling is left anywhere in a text.

    Args:
        text (str): Output of the redactor.
        spelling (str): One spelling of the secret.

    Returns:
        bool: Whether any :data:`MIN_SECRET_LENGTH` consecutive characters of ``spelling``
            appear in ``text``.
    """
    edge = MIN_SECRET_LENGTH
    return any(spelling[i : i + edge] in text for i in range(len(spelling) - edge + 1))


def _offsets(spelling: str) -> range:
    """
    List the offsets a cut can split a spelling at.

    Args:
        spelling (str): One spelling of the secret.

    Returns:
        range: Every offset a cut can split it at: 1 to its length minus 1.
    """
    return range(1, len(spelling))


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

# (sink, bound, what must not be left raw, whether the controls are kept raw)
_PROFILE_ROWS = [
    (Sink.TERMINAL, TERMINAL_MAX_CHARS, _RAW_MULTI_LINE),
    (Sink.LOG, TEXT_MAX_CHARS, _RAW_ANY),
    (Sink.MESSAGE, NAME_MAX_CHARS, _RAW_ANY),
    (Sink.STORE, TEXT_MAX_CHARS, None),
    (Sink.DOCUMENT, None, _RAW_MULTI_LINE),
    (Sink.JSON, None, _RAW_JSON),
]


@pytest.mark.parametrize(("sink", "bound", "raw"), _PROFILE_ROWS, ids=[r[0] for r in _PROFILE_ROWS])
def test_each_profile_bounds_and_neutralizes(
    sink: Sink, bound: int | None, raw: re.Pattern[str] | None
) -> None:
    # positive control: the input holds every kind of character a profile treats
    assert _RAW_ANY.search(_OVERSIZED)
    assert "\ud800" in _OVERSIZED
    out = safe_text(_OVERSIZED, sink)
    assert "\ud800" not in out
    if bound is None:
        assert not out.endswith(TRUNCATION_MARKER)
        assert len(out) >= len(_OVERSIZED)
    else:
        assert out.endswith(TRUNCATION_MARKER)
        assert out.count("y") == bound - len(_HOSTILE)  # the bound counts the source
    if raw is None:  # STORE keeps the controls raw: they are neutralized where shown
        assert "\x1b" in out
        assert "\r\n" in out
    else:
        assert not raw.search(out)


def test_the_terminal_profile_escapes_line_breaks_on_one_line() -> None:
    assert "\n" in safe_text(_HOSTILE, Sink.TERMINAL)
    assert not _RAW_ANY.search(safe_text(_HOSTILE, Sink.TERMINAL, one_line=True))


@pytest.mark.parametrize(
    ("sink", "escapes_line_breaks"),
    [
        (Sink.LOG, True),
        (Sink.MESSAGE, True),
        (Sink.STORE, False),
        (Sink.DOCUMENT, False),
        (Sink.JSON, False),
    ],
)
def test_one_line_is_a_choice_of_the_terminal_profile_only(
    sink: Sink, escapes_line_breaks: bool
) -> None:
    # deviation 3: only TERMINAL reads one_line; the others ignore it either way
    for one_line in (False, True):
        out = safe_text("a\nb", sink, one_line=one_line)
        assert ("\n" not in out) is escapes_line_breaks


def test_a_limit_replaces_the_profile_bound() -> None:
    assert safe_text("x" * 100, Sink.STORE, limit=10) == "x" * 10 + TRUNCATION_MARKER
    assert safe_text("x" * 100, Sink.DOCUMENT, limit=10) == "x" * 10 + TRUNCATION_MARKER


@pytest.mark.parametrize("sink", list(Sink))
def test_each_profile_is_idempotent_on_a_value_that_fits(sink: Sink) -> None:
    once = safe_text(_HOSTILE, sink)
    assert safe_text(once, sink) == once


@pytest.mark.parametrize("sink", [Sink.STORE, Sink.DOCUMENT, Sink.JSON])
def test_a_profile_without_escapes_past_the_bound_is_idempotent_when_cut(sink: Sink) -> None:
    # deviation 2: the escaping profiles may grow a cut value past the bound
    once = safe_text(_OVERSIZED, sink)
    assert safe_text(once, sink) == once


@pytest.mark.parametrize("sink", [Sink.TERMINAL, Sink.LOG, Sink.MESSAGE])
def test_an_escaping_profile_is_idempotent_on_a_cut_plain_value(sink: Sink) -> None:
    once = safe_text("x" * (2 * URL_MAX_CHARS), sink)
    assert safe_text(once, sink) == once


def test_the_store_profile_is_the_field_types() -> None:
    adapter = TypeAdapter(Text)
    assert safe_text(_OVERSIZED, Sink.STORE) == adapter.validate_python(_OVERSIZED)
    assert safe_text(_OVERSIZED, Sink.STORE) == store_text(_OVERSIZED, TEXT_MAX_CHARS)


def test_the_json_profile_is_the_json_escape() -> None:
    document = '{"a": "\x85\u202e"}'
    assert safe_text(document, Sink.JSON) == escape_json_controls(document)
    assert safe_text(document, Sink.JSON) == '{"a": "\\u0085\\u202e"}'


# ---------------------------------------------------------------------------
# Order
# ---------------------------------------------------------------------------


def test_a_cut_on_a_control_character_keeps_its_escape_whole() -> None:
    value = "a" * (TERMINAL_MAX_CHARS - 1) + "\x1b" + "b" * 100
    # positive control: cutting the escaped text splits the escape
    escaped_then_cut = store_text(show_controls(value), TERMINAL_MAX_CHARS)
    assert escaped_then_cut.endswith("\\" + TRUNCATION_MARKER)
    assert safe_text(value, Sink.TERMINAL) == "a" * (TERMINAL_MAX_CHARS - 1) + "\\x1b" + (
        TRUNCATION_MARKER
    )


def test_the_redaction_runs_before_the_bound() -> None:
    # the cut would leave 3 characters of the secret, under the fragment floor
    value = _FILL * (NAME_MAX_CHARS - 3) + _SECRET + _FILL * 200
    redactor = Redactor([_SECRET])
    # positive control: bounding first leaves the fragment
    assert _SECRET[:3] in redactor(store_text(value, NAME_MAX_CHARS))
    out = safe_text(value, Sink.MESSAGE, redactor=redactor)
    assert _SECRET[:3] not in out
    assert out.startswith(_FILL * (NAME_MAX_CHARS - 3) + REDACTED[:3])


# ---------------------------------------------------------------------------
# Redaction: whole secrets
# ---------------------------------------------------------------------------


def test_a_whole_secret_away_from_any_cut_is_redacted_whole() -> None:
    redactor = Redactor([_SECRET])
    for spelling in _SPELLINGS:
        assert redactor(f"title {spelling} end") == f"title {REDACTED} end"
    assert redactor.hits == len(_SPELLINGS)


def test_a_text_without_the_secret_is_left_alone_and_not_counted() -> None:
    redactor = Redactor([_SECRET])
    assert redactor("nothing here\u2026 at all...") == "nothing here\u2026 at all..."
    assert redactor.hits == 0


def test_a_short_secret_is_ignored_and_an_empty_redactor_changes_nothing() -> None:
    redactor = Redactor(["abc", ""])
    assert redactor.empty
    assert redactor("abc\u2026 abc") == "abc\u2026 abc"
    assert redactor.optional(None) is None
    assert Redactor([_SECRET]).optional(_SECRET) == REDACTED


# ---------------------------------------------------------------------------
# Redaction: the cut rule
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "limit"),
    [(Name, NAME_MAX_CHARS), (Text, TEXT_MAX_CHARS), (Url, URL_MAX_CHARS)],
    ids=["Name", "Text", "Url"],
)
def test_no_fragment_survives_a_field_bound(field: object, limit: int) -> None:
    adapter: TypeAdapter[str] = TypeAdapter(field)
    redactor = Redactor([_SECRET])
    for spelling in _SPELLINGS:
        for offset in _offsets(spelling):
            cut = adapter.validate_python(_FILL * (limit - offset) + spelling + _FILL * 40)
            # positive control: the bound split the spelling at this offset
            assert cut == _FILL * (limit - offset) + spelling[:offset] + TRUNCATION_MARKER
            out = redactor(cut)
            assert out.endswith(TRUNCATION_MARKER)
            if offset >= MIN_SECRET_LENGTH:
                assert not _fragment_left(out, spelling), (spelling, offset)
                assert out.endswith(REDACTED + TRUNCATION_MARKER)
            else:  # a fragment of 1-3 characters is under the floor, as a whole secret is
                assert out == cut


@pytest.mark.parametrize("cut_edges", [False, True])
def test_no_fragment_survives_the_evidence_bound(cut_edges: bool) -> None:
    redactor = Redactor([_SECRET])
    limit = 4096
    for spelling in _SPELLINGS:
        for offset in range(MIN_SECRET_LENGTH, len(spelling)):
            item = EvidenceItem.of("body", _FILL * (limit - offset) + spelling + _FILL * 40)
            assert item.content.endswith(spelling[:offset] + EVIDENCE_MARKER)
            out = redactor(item.content, cut_edges=cut_edges)
            assert not _fragment_left(out, spelling), (spelling, offset)
            assert out.endswith(REDACTED + EVIDENCE_MARKER)


@pytest.mark.parametrize("marker", CUT_MARKERS)
def test_no_fragment_survives_on_either_side_of_a_marker(marker: str) -> None:
    redactor = Redactor([_SECRET])
    for spelling in _SPELLINGS:
        for offset in _offsets(spelling):
            prefix, suffix = spelling[:offset], spelling[offset:]
            before = redactor(f"{_FILL * 3}{prefix}{marker}{_FILL * 3}")
            after = redactor(f"{_FILL * 3}{marker}{suffix}{_FILL * 3}")
            if len(prefix) >= MIN_SECRET_LENGTH:
                assert before == f"{_FILL * 3}{REDACTED}{marker}{_FILL * 3}", (spelling, offset)
            else:
                assert prefix in before
            if len(suffix) >= MIN_SECRET_LENGTH:
                assert after == f"{_FILL * 3}{marker}{REDACTED}{_FILL * 3}", (spelling, offset)
            else:
                assert suffix in after


def test_the_evidence_edges_are_cuts_only_when_asked() -> None:
    redactor = Redactor([_SECRET])
    for spelling in _SPELLINGS:
        for offset in range(MIN_SECRET_LENGTH, len(spelling) - MIN_SECRET_LENGTH + 1):
            starts_inside = spelling[offset:] + _FILL * 3
            ends_inside = _FILL * 3 + spelling[:offset]
            assert redactor(starts_inside, cut_edges=True) == REDACTED + _FILL * 3
            assert redactor(ends_inside, cut_edges=True) == _FILL * 3 + REDACTED
            # positive control: a title that merely ends with the first letters is left alone
            assert redactor(ends_inside) == ends_inside
            assert redactor(starts_inside) == starts_inside


def test_a_fragment_counts_as_a_redacted_field() -> None:
    redactor = Redactor([_SECRET])
    redactor(f"{_FILL}{_SECRET[:5]}\u2026")
    redactor(f"Welcome {_SECRET[:5]}")  # no cut, no change
    assert redactor.hits == 1


def test_overlapping_fragments_become_one_redaction() -> None:
    # the suffix after the first marker and the prefix before the second overlap
    redactor = Redactor(["abcdXabcd"])
    assert redactor("\u2026abcdX\u2026") == f"\u2026{REDACTED}\u2026"


def test_touching_fragments_become_one_redaction() -> None:
    # the suffix "efgh" after the start ends where the prefix "abcd" before the marker begins
    redactor = Redactor(["abcdefgh"])
    assert redactor("efghabcd...", cut_edges=True) == f"{REDACTED}..."


def test_a_fragment_inside_a_longer_one_does_not_shorten_it() -> None:
    # a secret holding a marker: the suffix after the start covers the whole text, and the
    # prefix "abcd" before the marker sits inside it
    redactor = Redactor(["abcdXabcd...QQ"])
    assert redactor("Xabcd...QQ", cut_edges=True) == REDACTED


def test_the_longest_fragment_at_a_cut_is_redacted() -> None:
    # "abcdabcdz" has the prefixes "abcd" and "abcdabcd" ending at the same cut
    redactor = Redactor(["abcdabcdz"])
    assert redactor("~abcdabcd\u2026") == f"~{REDACTED}\u2026"
    assert redactor("\u2026bcdabcdz~", cut_edges=False) == f"\u2026{REDACTED}~"


def test_a_fragment_longer_than_the_text_before_the_cut_is_not_read_from_the_end() -> None:
    redactor = Redactor(["zzzzWXYZq"])
    # "WXYZ" ends the prefix "zzzzWXYZ", 8 long, but only 4 characters stand before the cut
    assert redactor("WXYZ\u2026") == "WXYZ\u2026"
    # positive control: with the whole prefix before the cut, it is found
    assert redactor("zzzzWXYZ\u2026") == f"{REDACTED}\u2026"


def test_a_fragment_that_starts_the_text_is_redacted() -> None:
    # the cut is 4 characters in: the whole text before it is the fragment
    redactor = Redactor(["abcdefgh"])
    assert redactor("abcd\u2026") == f"{REDACTED}\u2026"


def test_fragments_apart_stay_apart() -> None:
    redactor = Redactor(["abcdefgh"])
    assert redactor("abcd\u2026middle\u2026efgh") == f"{REDACTED}\u2026middle\u2026{REDACTED}"


def test_a_run_of_dots_longer_than_a_marker_is_a_cut_at_each_offset() -> None:
    # "......" holds "..." four times; the fragment follows the last one
    redactor = Redactor(["abcdefgh"])
    assert redactor("......efgh") == f"......{REDACTED}"


@pytest.mark.parametrize(
    "secrets",
    [["XXXXXXXXabcdefgh", "Yabcd"], ["XXXXXXXXXXXXabcd", "Yabcdefgh"]],
    ids=["longest-first", "longest-last"],
)
def test_the_longest_suffix_wins_across_secrets(secrets: list[str]) -> None:
    # both secrets have a suffix starting "abcd" at the cut: "abcdefgh" must win over "abcd"
    assert Redactor(secrets)("\u2026abcdefgh") == f"\u2026{REDACTED}"


@pytest.mark.parametrize(
    "secrets",
    [["abcdefghXXXXXXXX", "efghY"], ["efghXXXXXXXXXXXX", "abcdefghY"]],
    ids=["longest-first", "longest-last"],
)
def test_the_longest_prefix_wins_across_secrets(secrets: list[str]) -> None:
    # both secrets have a prefix ending "efgh" at the cut: "abcdefgh" must win over "efgh"
    assert Redactor(secrets)("~abcdefgh\u2026") == f"~{REDACTED}\u2026"


def _snippet_helpers() -> Iterator[tuple[str, Callable[[str], str], str]]:
    """
    Yield the snippet helpers of the checks.

    Yields:
        tuple[str, Callable[[str], str], str]: A name, a helper that cuts a snippet out of a
            body, and the anchor the helper centres on.
    """
    envelope = object.__new__(EnvelopeScanner)
    anchor = "ANCHOR!"
    yield "xss", lambda body: xss._snippet(body, anchor), anchor
    yield "cmdi", lambda body: cmdi._snippet(body, body.find(anchor)), anchor
    yield "ssrf", lambda body: ssrf._snippet(body, body.find(anchor)), anchor
    yield "upload", lambda body: upload._snippet(body, anchor), anchor
    yield "upload-unmarked", lambda body: upload._snippet(body, "absent"), anchor
    yield "envelope", lambda body: envelope._around_sentinel(body), _SENTINEL


@pytest.mark.parametrize(
    ("helper", "anchor"),
    [(h, a) for _, h, a in _snippet_helpers()],
    ids=[name for name, _, _ in _snippet_helpers()],
)
def test_no_fragment_survives_a_snippet_helper(helper: Callable[[str], str], anchor: str) -> None:
    redactor = Redactor([_SECRET])
    split_at: set[int] = set()
    for spelling in _SPELLINGS:
        for pad in range(0, 260):
            for body in (
                anchor + _FILL * pad + spelling + _FILL * 300,  # cut after the anchor
                _FILL * 300 + spelling + _FILL * pad + anchor + _FILL * 300,  # cut before it
            ):
                snippet = helper(body)
                if spelling in snippet or not _fragment_left(snippet, spelling):
                    continue
                split_at.add(pad)
                assert not _fragment_left(redactor(snippet, cut_edges=True), spelling), (
                    spelling,
                    pad,
                )
    # positive control: the sweep did cut a spelling, leaving a fragment of 4 or more
    assert split_at


# ---------------------------------------------------------------------------
# Traceback
# ---------------------------------------------------------------------------


class _Unprintable(Exception):
    """An exception whose message cannot be rendered."""

    def __str__(self) -> str:
        raise RuntimeError("no")


def _hostile_chain() -> BaseException:
    """
    Build a chain of hostile exceptions with a group at its end.

    Returns:
        BaseException: A group raised from a cause raised while handling a context; the
            messages and the note hold line breaks, ESC and a bidirectional override.
    """
    try:
        try:
            raise OSError("first\nINFO forged record \x1b[31m")
        except OSError:
            try:
                raise ValueError("second \u202eevil")
            except ValueError as cause:
                group = ExceptionGroup("group\nmsg", [TypeError("member\x1bone"), KeyError("k\nk")])
                group.add_note("note\nwith a break \x1b")
                raise group from cause
    except ExceptionGroup as exc:
        return exc
    raise AssertionError("unreachable")


def _frame_lines(exc: BaseException) -> int:
    """
    Count the lines Python writes for an exception's stack.

    Args:
        exc (BaseException): A raised exception.

    Returns:
        int: How many lines Python writes for its stack.
    """
    return sum(len(e.rstrip("\n").split("\n")) for e in traceback.format_tb(exc.__traceback__))


def test_the_traceback_keeps_each_exception_on_its_lines() -> None:
    group = _hostile_chain()
    cause = group.__cause__
    assert cause is not None and cause.__context__ is not None
    context = cause.__context__
    out = safe_traceback(group)
    lines = out.split("\n")
    expected = (
        (1 + _frame_lines(context) + 1)  # OSError
        + 3  # "During handling..." with its blank lines
        + (1 + _frame_lines(cause) + 1)  # ValueError
        + 3  # "The above exception..." with its blank lines
        + (1 + _frame_lines(group) + 1 + 1)  # the group, its headline and its note
        + 2 * (1 + 1)  # each member: its header and its headline (never raised: no stack)
    )
    assert len(lines) == expected
    assert not _RAW_ANY.search(out.replace("\n", ""))
    assert "OSError: first\\x0aINFO forged record \\x1b[31m" in lines
    assert "ValueError: second \\u202eevil" in lines
    assert "note\\x0awith a break \\x1b" in lines
    assert "--- sub-exception 2 of 2 ---" in lines
    # positive control: Python's own format splits the messages and keeps the raw characters
    python = "".join(traceback.format_exception(group))
    assert "\x1b" in python
    assert len(python.rstrip("\n").split("\n")) > len(lines)


def test_the_traceback_is_bounded() -> None:
    previous: BaseException | None = None
    for _ in range(10):
        exc = ValueError("x" * (2 * TEXT_MAX_CHARS))
        exc.__context__ = previous
        previous = exc
    assert previous is not None
    out = safe_traceback(previous)
    assert out.endswith(TRUNCATION_MARKER)
    assert len(out) <= URL_MAX_CHARS + len(TRUNCATION_MARKER)
    first = out.split("\n")[0]
    assert first == "ValueError: " + "x" * (TEXT_MAX_CHARS - len("ValueError: ")) + (
        TRUNCATION_MARKER
    )


def _filled_to(size: int) -> ValueError:
    """
    Build an exception whose traceback has a given length.

    Args:
        size (int): The length its traceback must have.

    Returns:
        ValueError: An exception, never raised, whose notes make its traceback ``size``
            characters long, line breaks included.
    """
    exc = ValueError("x")
    exc.__notes__ = ["n" * 1000] * (size // 1001 - 1)
    exc.__notes__.append("n" * (size - len(safe_traceback(exc)) - 1))
    return exc


def test_a_traceback_of_exactly_the_bound_is_kept_whole() -> None:
    exact = _filled_to(URL_MAX_CHARS)
    out = safe_traceback(exact)
    assert len(out) == URL_MAX_CHARS
    assert not out.endswith(TRUNCATION_MARKER)
    # one character more cuts the last line, and what is kept fits the bound
    over = _filled_to(URL_MAX_CHARS)
    over.__notes__[-1] += "n"
    cut = safe_traceback(over)
    assert cut.endswith("\n" + TRUNCATION_MARKER)
    assert len(cut) - len("\n" + TRUNCATION_MARKER) <= URL_MAX_CHARS
    assert cut.count("\n") == out.count("\n")


def test_an_exception_without_a_message_is_named_alone() -> None:
    assert safe_traceback(ValueError()) == "ValueError"
    assert safe_traceback(ValueError("")) == "ValueError"
    # positive control: Python writes the bare name too
    assert traceback.format_exception_only(ValueError()) == ["ValueError\n"]


def test_the_traceback_ends_a_cycle_and_names_an_unprintable_exception() -> None:
    first, second = ValueError("one"), _Unprintable()
    first.__context__, second.__context__ = second, first
    out = safe_traceback(first)
    assert out.split("\n") == [
        f"{__name__}._Unprintable: <str() failed>",
        "",
        "During handling of the above exception, another exception occurred:",
        "",
        "ValueError: one",
    ]


def test_a_suppressed_context_is_left_out() -> None:
    try:
        try:
            raise KeyError("hidden")
        except KeyError:
            raise ValueError("shown") from None
    except ValueError as exc:
        out = safe_traceback(exc)
    assert "hidden" not in out
    assert "ValueError: shown" in out


def test_a_wide_and_a_deep_group_are_cut_as_python_cuts_them() -> None:
    wide = ExceptionGroup("wide", [ValueError(str(i)) for i in range(20)])
    out = safe_traceback(wide).split("\n")
    assert "--- sub-exception 15 of 20 ---" in out
    assert "--- sub-exception 16 of 20 ---" not in out
    assert out[-1] == "--- and 5 more sub-exceptions ---"
    deep: BaseException = ValueError("bottom")
    for level in range(12):
        deep = ExceptionGroup(f"level {level}", [deep])
    text = safe_traceback(deep)
    assert "... (exception groups nested deeper than 10)" in text
    assert "bottom" not in text


def _nested(levels: int) -> BaseException:
    """
    Wrap an exception in a number of exception groups.

    Args:
        levels (int): How many exception groups wrap the innermost exception.

    Returns:
        BaseException: ``ValueError("bottom")`` inside ``levels`` groups.
    """
    deep: BaseException = ValueError("bottom")
    for level in range(levels):
        deep = ExceptionGroup(f"level {level}", [deep])
    return deep


@pytest.mark.parametrize(("levels", "shown"), [(10, True), (11, False)])
def test_the_group_depth_stops_where_python_stops(levels: int, shown: bool) -> None:
    python = "".join(traceback.format_exception(_nested(levels)))
    assert ("bottom" in python) is shown
    assert ("bottom" in safe_traceback(_nested(levels))) is shown


@pytest.mark.parametrize(("width", "more"), [(15, None), (16, "--- and 1 more sub-exceptions ---")])
def test_the_group_width_stops_where_python_stops(width: int, more: str | None) -> None:
    group = ExceptionGroup("wide", [ValueError(str(i)) for i in range(width)])
    python = "".join(traceback.format_exception(group))
    assert ("and 1 more exception" in python) is (more is not None)
    out = safe_traceback(group).split("\n")
    assert f"--- sub-exception 15 of {width} ---" in out
    if more is None:
        assert not any("more sub-exceptions" in line for line in out)
    else:
        assert out[-1] == more


# ---------------------------------------------------------------------------
# Log filter
# ---------------------------------------------------------------------------


@pytest.fixture
def logger(request: pytest.FixtureRequest) -> Iterator[logging.Logger]:
    """
    Give each test its own logger from get_logger.

    Yields:
        logging.Logger: A logger named for the test, from :func:`get_logger`, at ``DEBUG``;
            its filters are removed afterwards.
    """
    log = get_logger(f"webvigil.test_output.{request.node.name}")
    log.setLevel(logging.DEBUG)
    yield log
    for item in list(log.filters):
        log.removeFilter(item)
    log.setLevel(logging.NOTSET)


def test_the_filter_renders_the_message_once_and_treats_it(
    logger: logging.Logger, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG):
        logger.debug("claimed %s for %d", "a\x1b[2Jb\nINFO forged", 7)
    (record,) = caplog.records
    assert record.args == ()
    assert record.getMessage() == "claimed a\\x1b[2Jb\\x0aINFO forged for 7"
    assert "\x1b" not in caplog.text


def test_the_filter_bounds_the_message(
    logger: logging.Logger, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG):
        logger.info("%s", "x" * (2 * TEXT_MAX_CHARS))
    (record,) = caplog.records
    assert record.getMessage() == "x" * TEXT_MAX_CHARS + TRUNCATION_MARKER


def test_the_filter_leaves_a_message_that_cannot_be_rendered(
    logger: logging.Logger, caplog: pytest.LogCaptureFixture
) -> None:
    # positive control: logging reports the formatting error itself (caplog raises it)
    with caplog.at_level(logging.DEBUG), pytest.raises(TypeError):
        logger.info("%d", "not a number")
    (record,) = caplog.records
    assert record.msg == "%d"
    assert record.args == ("not a number",)


def test_the_filter_rebuilds_the_traceback(
    logger: logging.Logger, caplog: pytest.LogCaptureFixture
) -> None:
    group = _hostile_chain()
    with caplog.at_level(logging.DEBUG):
        try:
            raise group
        except ExceptionGroup:
            logger.exception("scan failed")
    (record,) = caplog.records
    assert record.exc_text == safe_traceback(group)
    assert not _RAW_ANY.search(caplog.text.replace("\n", ""))
    assert "OSError: first\\x0aINFO forged record" in caplog.text


def test_the_filter_skips_an_empty_exc_info() -> None:
    # outside an ``except``, ``exc_info=True`` gives ``(None, None, None)``: nothing to rebuild
    record = logging.LogRecord("x", logging.ERROR, __file__, 1, "m", (), (None, None, None))
    assert SafeLogFilter().filter(record)
    assert record.exc_text is None
    # positive control: a real exception is rebuilt
    error = ValueError("v")
    raised = logging.LogRecord("x", logging.ERROR, __file__, 1, "m", (), (ValueError, error, None))
    SafeLogFilter().filter(raised)
    assert raised.exc_text == "ValueError: v"


def test_get_logger_attaches_one_filter_and_keeps_level_and_handlers() -> None:
    log = logging.getLogger("webvigil.test_output.attach")
    handler = logging.NullHandler()
    log.addHandler(handler)
    log.setLevel(logging.WARNING)
    try:
        assert get_logger(log.name) is log
        assert get_logger(log.name) is log
        assert sum(isinstance(item, SafeLogFilter) for item in log.filters) == 1
        assert log.level == logging.WARNING
        assert log.handlers == [handler]
    finally:
        log.removeHandler(handler)
        for item in list(log.filters):
            log.removeFilter(item)
        log.setLevel(logging.NOTSET)
