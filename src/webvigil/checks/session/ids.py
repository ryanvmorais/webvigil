"""
The analysers that judge a session id (spec 020, RF-03 / RF-04, ADR-6): pure functions, no I/O.

``judge_value`` looks at one id on its own; ``judge_samples`` looks at several anonymous visits
of the same cookie. A rule fires when the id **cannot be good**, never when it is merely less
than ideal: the entropy estimate is the *capacity* of the alphabet the id uses (so 16 lower-case
hex characters, exactly 64 bits, pass), and the structure rules (numeric, repeating, a counter,
a timestamp) are what catch an id that uses a large alphabet badly.

None of these functions returns the value, a part of it, or a hash of it: a rule is a code, a
sentence and a severity, and the callers add the length and the estimated bits.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import pairwise

from webvigil.core.findings import Severity

MIN_LENGTH = 16
MIN_BITS = 64
# 2001-01-01 .. 2100-01-01, in seconds and in milliseconds: the range a timestamp id lives in.
_EPOCH_S = (978_307_200, 4_102_444_800)
_EPOCH_MS = (_EPOCH_S[0] * 1000, _EPOCH_S[1] * 1000)
_COUNTER_MAX = 10**9
_MAX_BLOCK = 4  # the longest repeated block the "repeating" rule looks for
_MIN_REPEAT = 8  # a block repeat needs at least this many characters to count
_STEP_SPREAD = 4  # a sequence's largest step may be at most this many times its smallest
_MIN_SAMPLES = 3
_MIN_VARIANCE_LENGTH = 8
_CONSTANT_SHARE = 0.5  # half the positions equal in every sample is "low variance"

# (name, size, test): the smallest alphabet that contains every character wins.
_ALPHABETS: tuple[tuple[str, int, re.Pattern[str]], ...] = (
    ("digits", 10, re.compile(r"^[0-9]+$")),
    ("lower hex", 16, re.compile(r"^[0-9a-f]+$")),
    ("upper hex", 16, re.compile(r"^[0-9A-F]+$")),
    ("lower base36", 36, re.compile(r"^[0-9a-z]+$")),
    ("upper base36", 36, re.compile(r"^[0-9A-Z]+$")),
    ("alphanumeric", 62, re.compile(r"^[0-9A-Za-z]+$")),
    ("base64url", 64, re.compile(r"^[0-9A-Za-z_-]+$")),
)
_PRINTABLE = ("printable ASCII", 95)


@dataclass(frozen=True, slots=True)
class Rule:
    """
    One reason an id (or a series of ids) looks weak.

    Attributes:
        code (str): A short stable identifier (``"numeric"``, ``"duplicates"``).
        text (str): The reason, in words, for the finding's evidence.
        severity (Severity): How serious this reason is on its own.
        sampled (bool): ``True`` for a rule that needs several samples to fire.
    """

    code: str
    text: str
    severity: Severity
    sampled: bool = False


def alphabet_of(value: str) -> tuple[str, int]:
    """
    Args:
        value (str): A session id.

    Returns:
        tuple[str, int]: The name and size of the smallest standard alphabet that contains
            every character of ``value`` (printable ASCII when none does).
    """
    for name, size, pattern in _ALPHABETS:
        if pattern.match(value):
            return name, size
    return _PRINTABLE


def estimated_bits(value: str) -> float:
    """
    Args:
        value (str): A session id.

    Returns:
        float: ``len(value) x log2(alphabet size)``: the *capacity* of the format the id uses,
            an upper bound on its entropy. Generous on purpose: a finding built on it is never
            about a good id.
    """
    _name, size = alphabet_of(value)
    return len(value) * math.log2(size)


def _repeating(value: str) -> bool:
    """
    Args:
        value (str): A session id.

    Returns:
        bool: ``True`` for one character repeated, or a 1 to 4 character block repeated over
            the whole value (``"abababababababab"``).
    """
    if len(value) < _MIN_REPEAT:
        return False
    return any(
        len(value) % size == 0 and value == value[:size] * (len(value) // size)
        for size in range(1, _MAX_BLOCK + 1)
    )


def _in_epoch(number: int) -> bool:
    """
    Args:
        number (int): A non-negative integer.

    Returns:
        bool: ``True`` when it reads as an epoch time in seconds or milliseconds.
    """
    return _EPOCH_S[0] <= number <= _EPOCH_S[1] or _EPOCH_MS[0] <= number <= _EPOCH_MS[1]


def judge_value(value: str) -> list[Rule]:
    """
    Judge one session id on its own (RF-03).

    Args:
        value (str): The id (never logged or returned).

    Returns:
        list[Rule]: Every rule that fires; empty for an id that passes.
    """
    rules: list[Rule] = []
    if len(value) < MIN_LENGTH:
        rules.append(Rule("short", f"shorter than {MIN_LENGTH} characters", Severity.MEDIUM))
    if estimated_bits(value) < MIN_BITS:
        rules.append(
            Rule(
                "low-entropy",
                f"fewer than {MIN_BITS} bits even at the alphabet's full capacity",
                Severity.MEDIUM,
            )
        )
    if value.isascii() and value.isdigit():
        rules.append(Rule("numeric", "digits only", Severity.HIGH))
        number = int(value)
        if len(value) in (10, 13) and _in_epoch(number):
            rules.append(Rule("timestamp", "reads as an epoch timestamp", Severity.HIGH))
        elif number < _COUNTER_MAX:
            rules.append(Rule("counter", "a small number, like a counter", Severity.HIGH))
    if _repeating(value):
        rules.append(Rule("repeating", "one character or block repeated", Severity.HIGH))
    return rules


def _integers(values: Sequence[str]) -> list[int] | None:
    """
    Args:
        values (Sequence[str]): Sampled ids.

    Returns:
        list[int] | None: The values as integers when every one is all digits, else ``None``.
    """
    if all(v.isascii() and v.isdigit() for v in values):
        return [int(v) for v in values]
    return None


def _constant_share(values: Sequence[str]) -> float:
    """
    Args:
        values (Sequence[str]): Sampled ids of the same length.

    Returns:
        float: The share of positions that hold the same character in every sample.
    """
    length = len(values[0])
    constant = sum(1 for i in range(length) if len({v[i] for v in values}) == 1)
    return constant / length


def judge_samples(values: Sequence[str]) -> list[Rule]:
    """
    Judge a series of anonymous visits to the same cookie (RF-04).

    Args:
        values (Sequence[str]): The ids, in the order they were issued (never logged).

    Returns:
        list[Rule]: Every series rule that fires; empty for fewer than three samples or a
            series that looks independent.
    """
    if len(values) < _MIN_SAMPLES:
        return []
    rules: list[Rule] = []
    repeated = len(values) - len(set(values))
    if repeated:
        rules.append(
            Rule(
                "duplicates",
                f"{repeated} of {len(values)} anonymous visits got an id another visit had",
                Severity.HIGH,
                sampled=True,
            )
        )
    numbers = _integers(values)
    if numbers is not None:
        steps = [b - a for a, b in pairwise(numbers)]
        if all(s > 0 for s in steps) or all(s < 0 for s in steps):
            sizes = [abs(s) for s in steps]
            if max(sizes) <= _STEP_SPREAD * min(sizes):
                rules.append(
                    Rule(
                        "sequence",
                        "consecutive visits got consecutive numbers",
                        Severity.HIGH,
                        True,
                    )
                )
            elif all(s > 0 for s in steps) and all(_in_epoch(n) for n in numbers):
                rules.append(
                    Rule("timestamp-series", "ids grow like timestamps", Severity.HIGH, True)
                )
    if (
        repeated < len(values) - 1
        and len({len(v) for v in values}) == 1
        and len(values[0]) >= _MIN_VARIANCE_LENGTH
        and _constant_share(values) >= _CONSTANT_SHARE
    ):
        rules.append(
            Rule(
                "low-variance",
                "most characters are the same in every anonymous visit",
                Severity.MEDIUM,
                sampled=True,
            )
        )
    return rules


__all__ = [
    "MIN_BITS",
    "MIN_LENGTH",
    "Rule",
    "alphabet_of",
    "estimated_bits",
    "judge_samples",
    "judge_value",
]
