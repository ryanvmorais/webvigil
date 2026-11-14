"""
The Retire.js matchers cost time proportional to a script's size, and still find real libraries.

The text the matchers read comes from the scanned site: every script the fingerprint pass
downloads, and every script URL. The database patterns were written for JavaScript, with
open-ended repetitions that can cost time proportional to the square of a script's size, so the
loader bounds them (``_bound_repeats``) and the matcher reads a capped head of a body. Nothing is
mocked: the tests compile the real vendored database and time real patterns on real strings. The
time limit is far above what the bounded patterns need and far below what the unbounded ones needed
on the same input, so a slow CI runner cannot fail it and a regression cannot pass it.
"""

from __future__ import annotations

import re
import re._constants as sre_constants
import re._parser as sre_parser
import time
from datetime import date

import pytest

from webvigil.checks.deps import rules as rules_module
from webvigil.checks.deps._data import Provenance, load_raw_db
from webvigil.checks.deps.rules import (
    _BODY_MAX,
    _REPEAT_MAX,
    RetireJsRules,
    _bound_repeats,
    _Chain,
    _merge_one_char_alternations,
    _split_chain,
)

# Seconds a single pattern may take on one input.
_BUDGET_S = 5.0
# Characters of a script in the cost tests: more than an unbounded pattern could scan in the
# budget, and a fraction of what the matcher reads.
_SIZE = 64 * 1024
_PROVENANCE = Provenance(
    source_url="https://example/retire.js",
    retrieved=date(2026, 1, 1),
    license="Apache-2.0",
    attribution="test",
)


# ---------------------------------------------------------------------------
# _bound_repeats: what it rewrites and what it leaves alone
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "bounded"),
    [
        ("a*", f"a{{0,{_REPEAT_MAX}}}"),
        ("a+", f"a{{1,{_REPEAT_MAX}}}"),
        ("a+?", f"a{{1,{_REPEAT_MAX}}}?"),
        ("(?:a|b)*c", f"(?:a|b){{0,{_REPEAT_MAX}}}c"),
        ("a{3,}", f"a{{3,{_REPEAT_MAX}}}"),
        ("a{500,}", "a{500,500}"),
        ("a{2,5}", "a{2,5}"),
        ("a?b", "a?b"),
    ],
)
def test_an_open_ended_repetition_gets_a_bound(raw: str, bounded: str) -> None:
    """``*``, ``+`` and ``{n,}`` are bounded; ``?`` and a bounded ``{n,m}`` are not touched."""
    assert _bound_repeats(raw) == bounded


@pytest.mark.parametrize(
    "raw",
    [r"\*\+", r"[*+]", r"[^*+]", r"[]*]", r"[\]*+]", r"\\", r"\{2,\}"],
)
def test_escapes_and_character_classes_are_left_alone(raw: str) -> None:
    """A ``*`` or ``+`` that is a literal, or inside a class, is not a repetition."""
    assert _bound_repeats(raw) == raw


def test_the_bounded_form_matches_what_the_original_matched() -> None:
    """A version marker is still captured through the rewrite."""
    raw = r"/\*[\s]+marked v([0-9][0-9a-zA-Z._\-]*)"
    text = "/*\n  marked v4.3.0 (https://marked.js.org)"
    original = re.search(raw, text)
    bounded = re.search(_bound_repeats(raw), text)
    assert original is not None
    assert bounded is not None
    assert bounded.group(1) == original.group(1) == "4.3.0"


# ---------------------------------------------------------------------------
# _merge_one_char_alternations: a group of one-character branches becomes a class
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "merged"),
    [
        pytest.param("(?:\r|\n|.)+", r"[\s\S]+", id="line-breaks-and-any"),
        pytest.param("(?:.|\r|\n)+", r"[\s\S]+", id="any-first"),
        pytest.param(r"(?:\r|\n|.)", r"[\s\S]", id="escapes"),
        pytest.param(r"(?:\r|.)*", ".*", id="any-without-line-feed"),
        pytest.param(r"(?:\r|\t)*", r"[\r\t]*", id="no-any"),
        pytest.param(r"(?:[\s]|\n)+", r"[\n\s]+", id="space-class"),
        pytest.param(r"[\]](?:\r|.)", r"[\]].", id="after-a-class"),
    ],
)
def test_a_group_of_one_character_branches_becomes_a_class(raw: str, merged: str) -> None:
    """The group is replaced by the class that matches what one of its branches matches."""
    assert _merge_one_char_alternations(raw) == merged


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(r"\(?:\r|\n)", id="escaped-paren"),
        pytest.param("[(?:\r|\n)]", id="inside-a-class"),
        pytest.param(r"((?:ab|c))", id="longer-branch"),
        pytest.param(r"(\r|\n)+", id="capturing"),
    ],
)
def test_other_groups_are_left_alone(raw: str) -> None:
    """A group that is escaped, inside a class, capturing or with a longer branch is kept."""
    assert _merge_one_char_alternations(raw) == raw


@pytest.mark.parametrize("text", ["a\r\nb", "\r\r\n\n", "x" * 10, "\n"])
def test_the_merged_group_matches_what_the_group_matched(text: str) -> None:
    """On any text, the class and the group match the same span."""
    for raw in ("(?:\r|\n|.)+", "(?:.|\r|\n)+", r"(?:\r|.)+", r"(?:\r|\t)+"):
        original = re.search(raw, text)
        merged = re.search(_merge_one_char_alternations(raw), text)
        assert (original and original.span()) == (merged and merged.span())


def _repeats_an_alternation(pattern: str) -> bool:
    """
    Tell whether a regex repeats a group of alternatives.

    Args:
        pattern (str): A compiled regex source.

    Returns:
        bool: ``True`` when a repetition's body is an alternation, the shape whose cost can grow
            exponentially with the run it repeats over.
    """

    def walk(items: list[tuple[object, object]]) -> bool:
        for op, value in items:
            if op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT):
                body = list(value[2])  # type: ignore[index]
                if len(body) == 1 and body[0][0] is sre_constants.SUBPATTERN:
                    body = list(body[0][1][-1])  # type: ignore[index]
                if len(body) == 1 and body[0][0] is sre_constants.BRANCH:
                    return True
                if walk(list(value[2])):  # type: ignore[index]
                    return True
            elif op is sre_constants.SUBPATTERN:
                if walk(list(value[-1])):  # type: ignore[index]
                    return True
            elif op is sre_constants.BRANCH and any(
                walk(list(branch)) for branch in value[1]  # type: ignore[index]
            ):
                return True
        return False

    return walk(list(sre_parser.parse(pattern)))


def test_no_vendored_pattern_repeats_an_alternation() -> None:
    """After the rewrite, no compiled pattern or piece repeats a group of alternatives."""
    offending = []
    for component in RetireJsRules.load()._components.values():
        for matcher in (*component.filecontent, *component.filename, *component.uri):
            pieces = matcher._pieces if isinstance(matcher, _Chain) else (matcher,)
            offending += [p.pattern for p in pieces if _repeats_an_alternation(p.pattern)]
    assert offending == []


def test_a_library_header_followed_by_a_long_run_of_line_breaks_is_read_quickly() -> None:
    """The easyXDM header, then line breaks up to the head, costs time proportional to it."""
    head = " * easyXDM\n * http://easyxdm.net/"
    text = head + "\r" * (_BODY_MAX - len(head))
    started = time.perf_counter()
    RetireJsRules.load().identify(body=text)
    assert time.perf_counter() - started < _BUDGET_S


def test_easyxdm_is_still_identified() -> None:
    """The rewritten easyXDM pattern still reads the version below its header."""
    body = (
        "/**\n * easyXDM\n * http://easyxdm.net/\n * Copyright(c) 2009-2011\n */\n"
        '(function(){var easyXDM={version:"2.4.19"};})();'
    )
    found = RetireJsRules.load().identify(body=body)
    assert ("easyXDM", "2.4.19") in [(d.name, d.version) for d in found]


# ---------------------------------------------------------------------------
# The vendored database: nothing is lost, and every pattern is cheap
# ---------------------------------------------------------------------------


def _raw_patterns() -> list[str]:
    """
    Returns:
        list[str]: Every extractor pattern in the vendored database, with the version
            placeholder expanded.
    """
    found: list[str] = []
    for component in load_raw_db().get("components", {}).values():
        for kind in ("filename", "filecontent", "uri"):
            found.extend(component.get("extractors", {}).get(kind, []))
    return [
        p.replace(rules_module._VERSION_PLACEHOLDER, rules_module._VERSION_GROUP) for p in found
    ]


def test_bounding_loses_no_pattern() -> None:
    """Every pattern the database holds that compiled before still compiles."""
    compilable = []
    for raw in _raw_patterns():
        try:
            re.compile(raw)
        except re.error:
            continue
        compilable.append(raw)
    kept = sum(len(rules_module._compile_all([raw])) for raw in compilable)
    assert kept == len(compilable) > 300


def test_every_vendored_pattern_reads_long_scripts_quickly() -> None:
    """Every compiled pattern, on long runs of the pieces open-ended repetitions follow."""
    shapes = {
        "spaces": " " * _SIZE,
        "line-breaks": "\n" * _SIZE,
        "slashes-and-spaces": "/ " * (_SIZE // 2),
        "digits": "1" * _SIZE,
        "letters": "a" * _SIZE,
    }
    worst = 0.0
    for component in RetireJsRules.load()._components.values():
        for pattern in (*component.filecontent, *component.filename, *component.uri):
            for text in shapes.values():
                started = time.perf_counter()
                pattern.search(text)
                worst = max(worst, time.perf_counter() - started)
    assert worst < _BUDGET_S


# ---------------------------------------------------------------------------
# The cap on what is read
# ---------------------------------------------------------------------------


def _rules_for(marker: str) -> RetireJsRules:
    """
    Args:
        marker (str): A content pattern with a ``§§version§§`` placeholder.

    Returns:
        RetireJsRules: Rules over one made-up library that this marker identifies.
    """
    raw = {"components": {"demo": {"extractors": {"filecontent": [marker]}, "vulnerabilities": []}}}
    return RetireJsRules.from_raw(raw, _PROVENANCE)


def test_a_marker_inside_the_head_is_found_and_one_past_it_is_not() -> None:
    """The content patterns read ``_BODY_MAX`` characters of a script."""
    rules = _rules_for(r"demo v§§version§§")
    marker = "demo v1.2.3"
    inside = "." * (_BODY_MAX - len(marker)) + marker
    past = "." * _BODY_MAX + marker
    assert [d.name for d in rules.identify(body=inside)] == ["demo"]
    assert rules.identify(body=past) == []


def test_a_script_url_past_the_path_cap_is_not_read() -> None:
    """The URI patterns read ``_PATH_MAX`` characters of a path, whatever the URL's length."""
    rules = RetireJsRules.load()
    url = "https://example.com/" + "1" * 200_000
    started = time.perf_counter()
    rules.identify(url=url)
    assert time.perf_counter() - started < _BUDGET_S


# ---------------------------------------------------------------------------
# Behaviour: real libraries are still recognised
# ---------------------------------------------------------------------------


def test_a_library_header_with_a_version_is_still_identified() -> None:
    """The vendored database finds jQuery from the comment at the top of the script."""
    detections = RetireJsRules.load().identify(
        url="https://example.com/js/app.js",
        body="/*! jQuery v3.6.0 | (c) OpenJS Foundation and other contributors */\n",
    )
    assert any(d.name == "jquery" and d.version == "3.6.0" for d in detections)


def test_a_library_in_the_file_name_is_still_identified() -> None:
    """The vendored database finds a library and version from the file name."""
    detections = RetireJsRules.load().identify(url="https://example.com/js/jquery-3.6.0.min.js")
    assert any(d.name == "jquery" and d.version == "3.6.0" for d in detections)


# ---------------------------------------------------------------------------
# Patterns made of pieces joined by "anything in between"
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "pieces"),
    [
        ("A(.*\n)*.*B", ["A", "B"]),
        ("A(?:.*\n)*.*B", ["A", "B"]),
        (r"A[\s\S]*B[\s\S]*C", ["A", "B", "C"]),
        (r"A[\s\S]{1,200}B", None),
        ("A(.*\n){1,3}B", None),
        (r"A[\s\S]*B|C", None),
        (r"(A[\s\S]*B)", None),
        (r"[\s\S]*B", None),
        ("plain", None),
    ],
)
def test_only_a_top_level_joint_splits_a_pattern(raw: str, pieces: list[str] | None) -> None:
    """A bounded gap, a joint inside a group and a top-level alternation keep the regex whole."""
    assert _split_chain(raw) == pieces


def test_a_joined_pattern_finds_its_last_piece_far_from_the_first() -> None:
    """The version comes from the first piece; the last one may sit hundreds of lines below."""
    rules = _rules_for("/\\*! Demo §§version§§(.*\n)*.*\\.demo\\.widget")
    far = "/*! Demo 1.9.2 */\n" + "var x = 1;\n" * 2000 + "$.demo.widget = {};\n"
    near = "/*! Demo 1.9.2 */\n$.demo.other = {};\n"
    detections = rules.identify(body=far)
    assert [(d.name, d.version) for d in detections] == [("demo", "1.9.2")]
    assert detections[0].marker.startswith("/*! Demo 1.9.2")
    assert rules.identify(body=near) == []


def test_the_vendored_joined_patterns_are_matched_piece_by_piece() -> None:
    """The jQuery UI widget patterns and the pdf.js API pattern are chains, and still match."""
    chained = {
        name
        for name, component in RetireJsRules.load()._components.items()
        for matcher in component.filecontent
        if isinstance(matcher, _Chain)
    }
    assert {"jquery-ui-autocomplete", "jquery-ui-dialog", "jquery-ui-tooltip", "pdf.js"} <= chained
    body = "/*! jQuery UI 1.9.2\n * http://jqueryui.com\n */\n" + "x;\n" * 900 + "$.ui.tooltip;\n"
    found = RetireJsRules.load().identify(body=body)
    assert ("jquery-ui-tooltip", "1.9.2") in [(d.name, d.version) for d in found]


@pytest.mark.parametrize(
    "unit",
    [
        pytest.param("/*\njQuery UI 1.0" + "a" * 50 + "\n", id="widget-header-lines"),
        pytest.param("apiVersion:'1.0',data,password,", id="api-version-pieces"),
    ],
)
def test_a_script_head_of_repeated_pieces_is_read_quickly(unit: str) -> None:
    """A full head made of the first pieces of the joined patterns, with no last piece."""
    text = (unit * (_BODY_MAX // len(unit) + 1))[:_BODY_MAX]
    rules = RetireJsRules.load()
    started = time.perf_counter()
    rules.identify(body=text)
    assert time.perf_counter() - started < _BUDGET_S
