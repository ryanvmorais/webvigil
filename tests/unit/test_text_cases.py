"""
The shared neutralization cases — spec 025, RF-07 / ADR-7.

``tests/data/text-controls-cases.json`` holds the cases that ``show_controls`` and the
dashboard's ``showControls`` (``web/src/lib/text.test.ts``) must both pass: every escaped range
and its edges, the characters just outside each range, tab, line feed and CRLF in both modes, a
valid surrogate pair, an empty string and text that already holds a literal escape. A range
added to one side and not to the other fails in whichever suite runs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from webvigil.core.text import show_controls

_CASES_FILE = Path(__file__).parent.parent / "data" / "text-controls-cases.json"
_CASES: list[dict[str, Any]] = json.loads(_CASES_FILE.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", _CASES, ids=[case["name"] for case in _CASES])
def test_show_controls_gives_the_shared_expectation(case: dict[str, Any]) -> None:
    assert show_controls(case["input"], one_line=case["one_line"]) == case["expected"]


def test_the_cases_file_holds_no_raw_control_character() -> None:
    # every input is a JSON escape, so the file reads the same in any editor or diff
    raw = _CASES_FILE.read_bytes()
    assert raw.isascii()
    assert not any(byte < 0x20 and byte != 0x0A for byte in raw)
