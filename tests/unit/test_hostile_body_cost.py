"""
Decoding a body, reading the HTML of a page and matching the error-page signatures cost time
proportional to them, or end in time.

The charset a response declares and the markup of a page come from the scanned site. A charset
whose codec decodes in time that grows faster than the body, markup that keeps the parser's open
elements growing, and mis-nested forms, buttons or selects that make each one's search read the
next ones again would each keep one response busy for hours, out of reach of every deadline the
scan has. A signature whose neighbouring repetitions can share the same text reads it again from
every place a match could start, on every page. Each test hands the real function a real string
and reads the result or the clock; the time limit is far above what the bounded code needs and
far below what the unbounded code needed on the same input, so a slow CI runner cannot fail it
and a regression cannot pass it.
"""

from __future__ import annotations

import codecs
import contextvars
import encodings
import itertools
import pkgutil
import re
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from webvigil.checks.disclosure import redaction
from webvigil.checks.disclosure.signatures import (
    _SCAN_MAX,
    ERROR_SIGNATURES,
    LISTING_SIGNATURES,
    match_error,
)
from webvigil.core import html
from webvigil.core.target import Target
from webvigil.crawler.forms import parse_forms_html
from webvigil.http.client import _TEXT_CHARSETS, decode_text

# Seconds one call may take. The bounded code finishes these inputs in well under a second.
_BUDGET_S = 2.0
_URL = "http://example.test/"
_TARGET = Target.parse(_URL)
_SRC = Path(__file__).resolve().parents[2] / "src" / "webvigil"


def _text_codecs() -> list[str]:
    """
    Returns:
        list[str]: The name of every text codec Python's registry holds.
    """
    names: set[str] = set()
    for module in pkgutil.iter_modules(encodings.__path__):
        try:
            info = codecs.lookup(module.name)
        except LookupError:
            continue
        if getattr(info, "_is_text_encoding", True):
            names.add(info.name)
    return sorted(names)


def _timed(call: Callable[[], object]) -> float:
    """
    Args:
        call (Callable[[], object]): What to time.

    Returns:
        float: Seconds the call took.
    """
    started = time.perf_counter()
    call()
    return time.perf_counter() - started


def _in_a_scan(call: Callable[[], object]) -> html.PartialParses:
    """
    Run ``call`` the way a scan runs a check: with its own count of documents read in part.

    Args:
        call (Callable[[], object]): What to run.

    Returns:
        html.PartialParses: What the call counted.
    """

    def scan() -> html.PartialParses:
        partial = html.track_partial_parses()
        call()
        return partial

    return contextvars.copy_context().run(scan)


@pytest.fixture
def no_late_parse() -> Iterator[None]:
    """A parse a test left running past its deadline ends before the next test starts."""
    yield
    for worker in list(html._running):
        worker.join(120)
    html._running.clear()


# ---------------------------------------------------------------------------
# The charset of a body
# ---------------------------------------------------------------------------


def test_a_charset_outside_the_web_encodings_reads_as_utf8_whatever_codec_it_names() -> None:
    """Every text codec of the registry that is not a web encoding gives the UTF-8 reading."""
    body = "café".encode()
    others = [name for name in _text_codecs() if name not in _TEXT_CHARSETS]
    assert others  # the registry holds codecs no browser decodes
    for name in others:
        assert decode_text(body, f"text/html; charset={name}") == "café", name
    # Control: a web encoding is still honoured, and decodes the same bytes its own way.
    assert decode_text(body, "text/html; charset=windows-1252") == "cafÃ©"
    assert decode_text(body, "text/html; charset=ISO-8859-1") == "cafÃ©"


def test_a_long_body_decodes_in_time_proportional_to_it_whatever_charset_it_names() -> None:
    """Half a MiB, in every text codec the registry holds, decodes within the budget in all."""
    body = b"<p>-" + b"a" * (512 * 1024)
    spent = sum(
        _timed(lambda name=name: decode_text(body, f"text/html; charset={name}"))
        for name in _text_codecs()
    )
    assert spent < _BUDGET_S


# ---------------------------------------------------------------------------
# Parsing the HTML of a page
# ---------------------------------------------------------------------------


def test_every_html_parse_of_the_engine_goes_through_parse_html() -> None:
    """No module but ``core/html.py`` builds the parser: each parse has the same deadline."""
    builds = re.compile(r"LexborHTMLParser\s*\(")
    elsewhere = [
        str(path.relative_to(_SRC))
        for path in sorted(_SRC.rglob("*.py"))
        if path.name != "html.py" or path.parent.name != "core"
        if builds.search(path.read_text(encoding="utf-8"))
    ]
    assert elsewhere == []
    assert builds.search((_SRC / "core" / "html.py").read_text(encoding="utf-8"))


@pytest.mark.usefixtures("no_late_parse")
def test_a_page_that_does_not_parse_in_time_is_read_in_its_first_part(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Markup that nests without end leaves the call within its deadline, its start read."""
    monkeypatch.setattr(html, "PARSE_TIMEOUT_S", 0.2)
    page = '<a href="/first">first</a>' + "<div>" * 45_000 + '<a href="/last">last</a>'
    links: list[str] = []

    def read() -> None:
        links.extend(node.attributes["href"] or "" for node in html.parse_html(page).css("a"))

    started = time.perf_counter()
    partial = _in_a_scan(read)
    assert time.perf_counter() - started < _BUDGET_S
    assert links == ["/first"]
    assert len(partial.late) == 1 and not partial.cut
    (warning,) = partial.warnings()
    assert "read only in their first 16 KiB" in warning


@pytest.mark.usefixtures("no_late_parse")
def test_while_a_late_parse_still_runs_a_long_page_is_read_in_its_first_part() -> None:
    """At most one parse outlives its deadline: until it ends, the next pages are read in part."""
    release = threading.Event()
    late = threading.Thread(target=release.wait, daemon=True)
    late.start()
    html._running.append(late)
    page = '<a href="/first">first</a>' + "<p>text</p>" * 4_000 + '<a href="/last">last</a>'
    trees: list[html.LexborHTMLParser] = []
    try:
        started = time.perf_counter()
        partial = _in_a_scan(lambda: trees.append(html.parse_html(page)))
        assert time.perf_counter() - started < _BUDGET_S  # no wait for a deadline either
        assert [node.attributes["href"] for node in trees[0].css("a")] == ["/first"]
        assert len(partial.late) == 1
    finally:
        release.set()
    late.join()
    # Control: once it has ended, the same page is parsed whole.
    tree = html.parse_html(page)
    assert [node.attributes["href"] for node in tree.css("a")] == ["/first", "/last"]


def test_a_page_past_the_parse_limit_is_parsed_up_to_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """The parser gets at most MAX_PARSE_CHARS of a page, and the scan counts the page."""
    monkeypatch.setattr(html, "MAX_PARSE_CHARS", 64 * 1024)
    page = '<a href="/first">first</a>' + "<p>text</p>" * 8_000 + '<a href="/last">last</a>'
    links: list[str] = []
    partial = _in_a_scan(
        lambda: links.extend(n.attributes["href"] or "" for n in html.parse_html(page).css("a"))
    )
    assert links == ["/first"]
    assert len(partial.cut) == 1 and not partial.late
    assert "parsed only up to it" in partial.warnings()[0]
    # Control: a page within the limit is parsed whole and not counted.
    short = '<a href="/first">first</a>' + "<p>text</p>" * 2_000 + '<a href="/last">last</a>'
    counted = _in_a_scan(lambda: html.parse_html(short))
    assert [n.attributes["href"] for n in html.parse_html(short).css("a")] == ["/first", "/last"]
    assert counted.warnings() == []
    # A page of exactly the limit is not cut either.
    exact = '<a href="/first">first</a>'
    exact += "x" * (64 * 1024 - len(exact) - len('<a href="/last">last</a>'))
    exact += '<a href="/last">last</a>'
    assert len(exact) == 64 * 1024
    counted = _in_a_scan(lambda: html.parse_html(exact))
    assert [n.attributes["href"] for n in html.parse_html(exact).css("a")] == ["/first", "/last"]
    assert counted.warnings() == []


def test_a_page_cut_outside_a_scan_is_parsed_without_being_counted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller outside a scan (a library user) gets the parsed page; there is nothing to count."""
    monkeypatch.setattr(html, "MAX_PARSE_CHARS", 64 * 1024)
    page = '<a href="/first">first</a>' + "<p>text</p>" * 8_000
    tree = contextvars.Context().run(html.parse_html, page)
    assert [n.attributes["href"] for n in tree.css("a")] == ["/first"]


def test_a_scan_counts_at_most_so_many_distinct_documents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The count remembers a bounded number of documents, so a scan's memory stays bounded."""
    monkeypatch.setattr(html, "MAX_PARSE_CHARS", 64 * 1024)
    monkeypatch.setattr(html, "_REMEMBERED", 2)
    pages = [f"<p>{n}</p>" + "<p>text</p>" * 8_000 for n in range(3)]
    partial = _in_a_scan(lambda: [html.parse_html(page) for page in pages])
    assert len(partial.cut) == 2
    # Control: under the bound, each distinct document counts once, a repeat not again.
    monkeypatch.setattr(html, "_REMEMBERED", 10)
    partial = _in_a_scan(lambda: [html.parse_html(page) for page in [*pages, pages[0]]])
    assert len(partial.cut) == 3


def test_an_error_of_the_parser_reaches_the_caller(monkeypatch: pytest.MonkeyPatch) -> None:
    """The worker thread hands an exception back rather than turning it into an empty page."""

    def broken(text: str) -> object:
        raise MemoryError("parser")

    monkeypatch.setattr(html, "LexborHTMLParser", broken)
    with pytest.raises(MemoryError):
        html.parse_html("<p>text</p>" * 4_000)


# ---------------------------------------------------------------------------
# Mis-nested forms, buttons and selects
# ---------------------------------------------------------------------------

# About 1.4 MB of elements below the nested ones, within the parse limit: enough that reading it
# again for each nested form, button or select takes seconds, while reading it once takes little.
_FILLER = "<i></i>" * 200_000


@pytest.mark.parametrize(
    "page",
    [
        pytest.param("<form><div></form>" * 500 + "<input name=q>" + _FILLER, id="forms"),
        pytest.param(
            "<form><input name=q>" + "<button>x<object>" * 1_000 + _FILLER + "</form>",
            id="buttons",
        ),
        pytest.param(
            "<form>"
            + "<select name=s><object>" * 1_000
            + "<option>o</option><i></i>" * 60_000
            + "</form>",
            id="selects",
        ),
    ],
)
def test_mis_nested_controls_are_read_in_time_proportional_to_the_page(page: str) -> None:
    """Each nested form, button or select reads its own part of the page, not the rest of it."""
    forms: list[object] = []
    assert _timed(lambda: forms.extend(parse_forms_html(page, _URL, _TARGET))) < _BUDGET_S
    assert forms


def test_a_control_inside_nested_forms_belongs_to_the_innermost_one_only() -> None:
    """As a browser has it: the nearest form around a control owns it, at any depth below it."""
    # The parser puts the inner form, and the controls after its end tag, inside the outer one.
    page = (
        '<form action="/outer"><div></form><form action="/inner">text<p><span>a</span>'
        '<input name="q"></p><div><input name="r"></div></form><input name="o">'
        '<select name="a"><div>pick</div><option>One</option></select>'
    )
    outer, inner = parse_forms_html(page, _URL, _TARGET)
    assert outer.action == "http://example.test/outer"
    assert [(field.name, field.value) for field in outer.fields] == [("o", ""), ("a", "One")]
    assert inner.action == "http://example.test/inner"
    assert [field.name for field in inner.fields] == ["q", "r"]


def test_a_button_inside_a_button_keeps_its_own_label() -> None:
    """The outer button's label is its own text, without the inner button's."""
    page = (
        '<form method="post"><button name="go">Save<object><button>Delete</button></object>'
        '</button><textarea name="t" type="submit" value="no"></textarea></form>'
    )
    (form,) = parse_forms_html(page, _URL, _TARGET)
    assert form.labels == ("Save", "Delete")
    # A button is a label, never a field; a textarea is a field, never a label.
    assert [field.name for field in form.fields] == ["t"]


def test_a_select_inside_a_select_keeps_its_own_options() -> None:
    """The outer select's value is its own first option, not the inner one's selected option."""
    page = (
        '<form><select name="a"><div>pick</div><option>One</option><object><select name="b">'
        "<option selected>Two</option></select></object></select></form>"
    )
    (form,) = parse_forms_html(page, _URL, _TARGET)
    assert [(field.name, field.value) for field in form.fields] == [("a", "One"), ("b", "Two")]


# ---------------------------------------------------------------------------
# The error-page and directory-listing signatures
# ---------------------------------------------------------------------------

# Seconds one body of ``_SCAN_MAX`` characters, shaped to make a signature backtrack, may take.
# The signatures finish each in tens of milliseconds; the ones they replaced took one to two
# seconds, on every page of a scan.
_SIGNATURE_BUDGET_S = 0.5
# The sweep builds many bodies from the pieces of every signature, so each one is short, and one
# search of it may take this long. The signatures take a few milliseconds on each.
_SWEEP_CHARS = 16 * 1024
_SWEEP_BUDGET_S = 0.05
# The parse tree of a compiled pattern, where its literal runs are read. ``re`` exposes no public
# parser; this is CPython's own (``sre_parse`` until 3.11), present in every version the CI runs.
_PATTERN_PARSER = re._parser
_SWEEP_FILLERS = (" ", "a", "1", ":", "(", "\n", "<", "_")
_SIGNATURE_TABLE = [
    pytest.param(signature.pattern, id=f"{signature.framework}-{index}")
    for index, signature in enumerate(ERROR_SIGNATURES)
] + [
    pytest.param(pattern, id=f"listing-{index}") for index, pattern in enumerate(LISTING_SIGNATURES)
]
# The patterns that mask a probe's evidence, swept up to the most text one call gives them.
_REDACTION_TABLE = [
    pytest.param(pattern, id=f"redaction-{name}")
    for name, pattern in (
        ("secret", redaction._SECRET_RE),
        ("kv", redaction._KV_RE),
        ("htpasswd", redaction._HTPASSWD_RE),
        ("userinfo", redaction._USERINFO_RE),
        ("assignment", redaction._ASSIGNMENT_RE),
        ("value", redaction._VALUE_RE),
    )
]


def _repeated(unit: str, chars: int) -> str:
    """
    Args:
        unit (str): The piece to repeat.
        chars (int): Length of the result.

    Returns:
        str: ``unit`` repeated and cut to ``chars`` characters.
    """
    return (unit * (chars // len(unit) + 1))[:chars]


def _literals(pattern: re.Pattern[str]) -> list[str]:
    """
    Args:
        pattern (re.Pattern[str]): A compiled signature.

    Returns:
        list[str]: Its six longest runs of literal characters (the words its matches are built
            of), read from the parse tree of the pattern.
    """
    found: set[str] = set()
    run: list[str] = []

    def flush() -> None:
        if "".join(run).strip():
            found.add("".join(run))
        run.clear()

    def walk(items: object) -> None:
        for op, value in items:
            if op is _PATTERN_PARSER.LITERAL:
                run.append(chr(value))
                continue
            flush()
            if op is _PATTERN_PARSER.SUBPATTERN:
                walk(value[-1])
            elif op is _PATTERN_PARSER.BRANCH:
                for branch in value[1]:
                    walk(branch)
                    flush()
            elif op in (_PATTERN_PARSER.MAX_REPEAT, _PATTERN_PARSER.MIN_REPEAT):
                walk(value[2])
            elif op in (_PATTERN_PARSER.ASSERT, _PATTERN_PARSER.ASSERT_NOT):
                # a lookaround's literals gate the rest: a body without them is never read
                walk(value[1])
        flush()

    walk(_PATTERN_PARSER.parse(pattern.pattern, pattern.flags))
    return sorted(found, key=lambda text: (-len(text), text))[:6]


def _shapes(pattern: re.Pattern[str]) -> list[str]:
    """
    Args:
        pattern (re.Pattern[str]): A compiled signature.

    Returns:
        list[str]: Units to repeat into a body: each literal of the pattern followed by one
            filler or a run of it, and each pair of literals with a filler or a long gap between
            them, which is where two neighbouring repetitions could share the text.
    """
    pieces = _literals(pattern)
    units = [
        piece + filler * count for piece in pieces for filler in _SWEEP_FILLERS for count in (1, 50)
    ]
    for first, second in itertools.product(pieces, repeat=2):
        for filler in (" ", "a", ":"):
            units += [first + filler + second, first + filler * 200 + second]
    return units


@pytest.mark.parametrize(
    "unit",
    [
        # Headings of the plain PHP form with " in " between them: the message and the file
        # path could each start at any of them.
        pytest.param("Fatal error: in :", id="php-fatal"),
        pytest.param("Deprecated: in :", id="php-deprecated"),
        # A Java exception name, then whitespace the message and the gap before "at" could
        # share: once with no message, once with a message ending before the whitespace.
        pytest.param("a.FooException:" + " " * 520, id="java-gap"),
        pytest.param("a.FooException: x" + " " * 300, id="java-message-gap"),
        # The same split for a Node.js message.
        pytest.param("Error:" + " " * 220, id="node-gap"),
    ],
)
def test_a_body_shaped_to_backtrack_a_signature_is_matched_in_time(unit: str) -> None:
    """The longest body the signatures read, repeating a shape built against one of them."""
    body = _repeated(unit, _SCAN_MAX)
    assert _timed(lambda: match_error(body)) < _SIGNATURE_BUDGET_S


@pytest.mark.parametrize("pattern", _SIGNATURE_TABLE)
def test_every_signature_reads_bodies_built_from_its_own_pieces_in_time(
    pattern: re.Pattern[str],
) -> None:
    """Each signature of both tables, on every body the sweep builds from its literals."""
    units = _shapes(pattern)
    assert len(units) > 20  # the pattern has literals to build from: the sweep is not empty
    for unit in units:
        body = _repeated(unit, _SWEEP_CHARS)
        spent = _timed(lambda body=body: pattern.search(body))
        if spent >= _SWEEP_BUDGET_S:  # a busy runner: the best of three decides
            spent = min(_timed(lambda body=body: pattern.search(body)) for _ in range(3))
        assert spent < _SWEEP_BUDGET_S, unit[:40]


@pytest.mark.parametrize("pattern", _REDACTION_TABLE)
def test_every_redaction_pattern_reads_bodies_built_from_its_own_pieces_in_time(
    pattern: re.Pattern[str],
) -> None:
    """Each pattern of the probe redaction, on the longest text one call reads (the JSON cap)."""
    units = _shapes(pattern)
    assert len(units) > 20  # the pattern has literals to build from: the sweep is not empty
    for unit in units:
        body = _repeated(unit, redaction._JSON_LIMIT)
        spent = _timed(lambda body=body: pattern.sub("", body))
        if spent >= _SWEEP_BUDGET_S:  # a busy runner: the best of three decides
            spent = min(_timed(lambda body=body: pattern.sub("", body)) for _ in range(3))
        assert spent < _SWEEP_BUDGET_S, unit[:40]
