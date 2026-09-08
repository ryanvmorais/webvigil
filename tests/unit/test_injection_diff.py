"""
The shared response-differential helpers — spec 014 ADR-3.

Pure functions over strings; no HTTP, no fixtures. ``two_sided_split`` is the
boolean rule (``sqli`` / ``xpath``), ``wider_then_same`` the result-set rule
(``ldap``). The move out of ``sqli.py`` is covered by the unchanged ``sqli``
tests; this file pins the helpers themselves.
"""

from __future__ import annotations

from webvigil.checks.injection.detect._diff import ratio, two_sided_split, wider_then_same

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
