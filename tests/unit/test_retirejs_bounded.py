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
import time
from datetime import date

import pytest

from webvigil.checks.deps import rules as rules_module
from webvigil.checks.deps._data import Provenance, load_raw_db
from webvigil.checks.deps.rules import _BODY_MAX, _REPEAT_MAX, RetireJsRules, _bound_repeats

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
