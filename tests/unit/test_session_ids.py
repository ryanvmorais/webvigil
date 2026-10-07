"""
The session-id analysers — spec 020 RF-03 / RF-04, ADR-6.

``judge_value`` and ``judge_samples`` are pure functions of strings, so the tests are tables:
a value (or a series) and the set of rule codes that must fire. The cases that matter are the
boundaries: the 16-character / 64-bit floor (16 lower-case hex characters pass, 15 do not), the
structure rules that catch a good-looking alphabet used badly, and a random series that must
fire nothing.
"""

from __future__ import annotations

import math

import pytest

from webvigil.checks.session.ids import (
    alphabet_of,
    estimated_bits,
    judge_samples,
    judge_value,
)
from webvigil.core.findings import Severity

_HEX32 = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"
_B64_22 = "Xk3_9aZq-1LmN0pR7sTuVw"

# (value, the rule codes that must fire)
_VALUES = [
    ("abc123", {"short", "low-entropy"}),
    ("a1b2c3d4e5f6071", {"short", "low-entropy"}),  # 15 hex characters: 60 bits
    ("a1b2c3d4e5f60718", set()),  # 16 hex characters: exactly 64 bits, the floor
    (_HEX32, set()),
    (_B64_22, set()),
    ("A1b2C3d4E5f6G7h8I9j0K1l2M3", set()),
    ("1234567890123456", {"low-entropy", "numeric"}),  # digits: 16 x 3.32 = 53 bits
    ("42", {"short", "low-entropy", "numeric", "counter"}),
    ("1700000000", {"short", "low-entropy", "numeric", "timestamp"}),
    ("1700000000123", {"short", "low-entropy", "numeric", "timestamp"}),  # epoch ms
    ("a" * 32, {"repeating"}),
    ("ab" * 16, {"repeating"}),
    ("abcd" * 8, {"repeating"}),
    ("", {"short", "low-entropy"}),
]


@pytest.mark.parametrize(("value", "codes"), _VALUES)
def test_a_value_fires_exactly_the_rules_that_apply(value: str, codes: set[str]) -> None:
    """The floor, the structure rules and the passes, one table."""
    assert {rule.code for rule in judge_value(value)} == codes


def test_severity_follows_the_rules_not_the_value() -> None:
    """A short alphanumeric id is MEDIUM; a numeric, repeating or counter-like one is HIGH."""
    top = {
        value: max((r.severity for r in judge_value(value)), default=None) for value, _ in _VALUES
    }
    assert top["abc123"] is Severity.MEDIUM
    assert top["42"] is Severity.HIGH
    assert top["a" * 32] is Severity.HIGH
    assert top[_HEX32] is None


_ALPHABETS = [
    ("0123", "digits", 10),
    ("0a1f", "lower hex", 16),
    ("0A1F", "upper hex", 16),
    ("0z9", "lower base36", 36),
    ("0Z9", "upper base36", 36),
    ("aZ09", "alphanumeric", 62),
    ("a_-Z9", "base64url", 64),
    ("a!b", "printable ASCII", 95),
]


@pytest.mark.parametrize(("value", "name", "size"), _ALPHABETS)
def test_the_alphabet_is_the_smallest_standard_one_that_holds_every_character(
    value: str, name: str, size: int
) -> None:
    """The estimate uses the alphabet's capacity: the smallest class that contains the value."""
    assert alphabet_of(value) == (name, size)
    assert estimated_bits(value) == pytest.approx(len(value) * math.log2(size))


# five independent random 128-bit hex ids
_RANDOM = [
    "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
    "03a7c1e95d2b48f6a0c9e1b3d5f7a2c4",
    "d41d8cd98f00b204e9800998ecf8427e",
    "5eb63bbbe01eeed093cb22bb8f5acdc3",
    "7c4a8d09ca3762af61e59520943dc264",
]

_SAMPLE_CASES = [
    (_RANDOM, set()),
    ([_RANDOM[0], _RANDOM[1], _RANDOM[0], _RANDOM[2]], {"duplicates"}),
    (["1001", "1002", "1003", "1004"], {"sequence"}),
    (["1004", "1003", "1002"], {"sequence"}),  # decreasing is a sequence too
    (["100", "103", "105", "109"], {"sequence"}),  # irregular, but within 4x of the smallest step
    (["100", "101", "900", "901"], set()),  # one huge jump: not a counter
    (
        ["1700000000", "1700000050", "1700001000", "1700002500"],
        {"timestamp-series", "low-variance"},
    ),
    (["samevalue12345678"] * 4, {"duplicates"}),  # identical: duplicates only, not low variance
    (["fixedprefix_AAAA", "fixedprefix_BBBB", "fixedprefix_CCCC"], {"low-variance"}),
    ([_HEX32, _RANDOM[1]], set()),  # fewer than three samples: nothing to say
    ([], set()),
]


@pytest.mark.parametrize(("values", "codes"), _SAMPLE_CASES)
def test_a_series_fires_exactly_the_series_rules_that_apply(
    values: list[str], codes: set[str]
) -> None:
    """Duplicates, sequences, timestamp series, low variance, and a random series that is clean."""
    assert {rule.code for rule in judge_samples(values)} == codes


def test_series_rules_are_marked_as_needing_samples() -> None:
    """Every rule from ``judge_samples`` says it is sampled; the value rules never do."""
    assert all(rule.sampled for rule in judge_samples(["1001", "1002", "1003"]))
    assert not any(rule.sampled for rule in judge_value("42"))
