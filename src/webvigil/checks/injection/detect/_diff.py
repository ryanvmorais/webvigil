"""
Shared response-differential helpers for the error/boolean detectors (spec 014, ADR-3).

``sqli`` (spec 006), ``ldap`` and ``xpath`` (spec 014) all confirm a blind
injection by comparing a TRUE-payload response and a FALSE-payload response
against the point's baseline. Two rules cover the cases:

* :func:`two_sided_split` — the classic boolean rule: TRUE stays close to the
  baseline, FALSE diverges. Used by ``sqli`` and ``xpath``.
* :func:`wider_then_same` — the result-set rule: TRUE returns materially *more*
  than the baseline (an ``*`` LDAP filter widens the match set), FALSE is
  unchanged. Used by ``ldap``.
"""

from __future__ import annotations

from difflib import SequenceMatcher

from webvigil.checks.injection.detect import normalize_body

_SIMILAR = 0.95  # "same as baseline" floor
_GAP = 0.90  # "diverged from baseline" ceiling
_WIDEN = 1.30  # "materially larger than baseline" factor


def ratio(a: str, b: str) -> float:
    """
    Args:
        a (str): First string.
        b (str): Second string.

    Returns:
        float: A fast upper-bound similarity ratio in ``[0, 1]``.
    """
    return SequenceMatcher(None, a, b).quick_ratio()


def two_sided_split(baseline_norm: str, true_body: str, false_body: str) -> bool:
    """
    The boolean rule: TRUE tracks the baseline, FALSE diverges from it.

    Args:
        baseline_norm (str): The normalised baseline body.
        true_body (str): The TRUE-payload response body (raw).
        false_body (str): The FALSE-payload response body (raw).

    Returns:
        bool: ``True`` when ``ratio(baseline, TRUE) >= 0.95`` and
            ``ratio(baseline, FALSE) <= 0.90``.
    """
    return (
        ratio(baseline_norm, normalize_body(true_body)) >= _SIMILAR
        and ratio(baseline_norm, normalize_body(false_body)) <= _GAP
    )


def wider_then_same(baseline_norm: str, baseline_len: int, true_body: str, false_body: str) -> bool:
    """
    The result-set rule: TRUE returns materially more than the baseline, FALSE is unchanged.

    Args:
        baseline_norm (str): The normalised baseline body.
        baseline_len (int): Length of the raw baseline body.
        true_body (str): The widening-payload response body (raw).
        false_body (str): The no-op-payload response body (raw).

    Returns:
        bool: ``True`` when ``len(TRUE) >= baseline_len * 1.30`` and
            ``ratio(baseline, FALSE) >= 0.95``.
    """
    return (
        len(true_body) >= baseline_len * _WIDEN
        and ratio(baseline_norm, normalize_body(false_body)) >= _SIMILAR
    )
