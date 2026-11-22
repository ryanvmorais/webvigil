"""
The shared response-differential helpers — spec 014 ADR-3.

Pure functions over strings; no HTTP, no fixtures. ``two_sided_split`` is the
boolean rule (``sqli`` / ``xpath``), ``status_split`` the status-class rule (``sqli``),
``wider_then_same`` the result-set rule (``ldap``). The move out of ``sqli.py`` is covered by
the unchanged ``sqli`` tests; this file pins the helpers themselves, each threshold at its
exact value.
"""

from __future__ import annotations

from webvigil.checks.injection.detect._diff import (
    ratio,
    status_split,
    two_sided_split,
    wider_then_same,
)

_BASE = "the quick brown fox jumps over the lazy dog " * 8
_DIVERGENT = "nothing here matches the original page at all " * 8


def test_ratio_is_one_for_identical_and_low_for_unrelated() -> None:
    """``ratio`` is 1.0 for identical strings and well below the floor for unrelated ones."""
    assert ratio(_BASE, _BASE) == 1.0
    assert ratio(_BASE, _DIVERGENT) < 0.9


def test_two_sided_split_true_tracks_baseline_false_diverges() -> None:
    """A TRUE response ~= baseline and a FALSE response that diverges is a split."""
    assert two_sided_split(_BASE, _BASE, _DIVERGENT) is True


def test_two_sided_split_rejects_a_one_sided_change() -> None:
    """FALSE staying close to the baseline (only TRUE moved) is not a split."""
    assert two_sided_split(_BASE, _DIVERGENT, _BASE) is False
    assert two_sided_split(_BASE, _BASE, _BASE) is False


def test_wider_then_same_true_grows_false_unchanged() -> None:
    """A TRUE body 30%+ larger than the baseline with an unchanged FALSE body is a widen."""
    wide = _BASE + _BASE  # 2x the baseline length
    assert wider_then_same(_BASE, len(_BASE), wide, _BASE) is True


def test_wider_then_same_rejects_a_small_growth_or_a_changed_false() -> None:
    """A marginal size bump, or a FALSE body that also moved, is not a widen."""
    barely = _BASE + "xx"
    assert wider_then_same(_BASE, len(_BASE), barely, _BASE) is False
    wide = _BASE + _BASE
    assert wider_then_same(_BASE, len(_BASE), wide, _DIVERGENT) is False


# A 40-character body with no long token, so ``normalize_body`` leaves it as it is. Each "b"
# turned into a "z" costs one matching character: 2 of 40 give exactly 0.95, 4 exactly 0.90.
_EDGE = ("ab " * 14)[:40]


def _edited(count: int) -> str:
    """
    Args:
        count (int): How many ``b`` characters of ``_EDGE`` become ``z``.

    Returns:
        str: The edited body, the same length as ``_EDGE``.
    """
    return _EDGE.replace("b", "z", count)


def test_the_edge_bodies_sit_exactly_on_the_thresholds() -> None:
    """The fixtures below rely on these ratios: 0.95, 0.925, 0.90 and 0.875."""
    assert [ratio(_EDGE, _edited(n)) for n in (2, 3, 4, 5)] == [0.95, 0.925, 0.90, 0.875]


def test_two_sided_split_includes_both_thresholds() -> None:
    """TRUE at exactly 0.95 still tracks the baseline; FALSE at exactly 0.90 still diverges."""
    assert two_sided_split(_EDGE, _edited(2), _edited(5)) is True
    assert two_sided_split(_EDGE, _EDGE, _edited(4)) is True
    assert two_sided_split(_EDGE, _edited(3), _edited(5)) is False  # TRUE just below 0.95
    assert two_sided_split(_EDGE, _EDGE, _edited(3)) is False  # FALSE just above 0.90


def test_status_split_needs_the_class_change_and_a_true_page_like_the_baseline() -> None:
    """Same class for TRUE, another class for FALSE, and TRUE at 0.95 or more of the baseline."""
    assert status_split(200, _EDGE, 200, _edited(2), 404) is True
    assert status_split(200, _EDGE, 200, _edited(3), 404) is False  # TRUE drifted from the page
    assert status_split(200, _EDGE, 200, _EDGE, 204) is False  # FALSE in the same class
    assert status_split(200, _EDGE, 302, _EDGE, 404) is False  # TRUE left the baseline's class


def test_wider_then_same_includes_both_thresholds() -> None:
    """TRUE at exactly 1.30 times the baseline widens; FALSE at exactly 0.95 is unchanged."""
    assert wider_then_same(_EDGE, 20, "x" * 26, _edited(2)) is True
    assert wider_then_same(_EDGE, 20, "x" * 25, _EDGE) is False  # just below 1.30
    assert wider_then_same(_EDGE, 20, "x" * 26, _edited(3)) is False  # FALSE just below 0.95
