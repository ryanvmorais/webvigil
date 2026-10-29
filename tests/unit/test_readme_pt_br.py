"""
Tests that ``README.pt-BR.md`` keeps the shape of ``README.md``.

``README.pt-BR.md`` is a translation, and a translation drifts: a section added to ``README.md``
that nobody carries over leaves Brazilian readers with an older tool than the one they installed.
The tests compare structure, never wording: the order of the headings, the rows of the two tables,
the commands of the shell blocks (they are not translated, so they must be equal), the cross-links
between the two files and the repository files the Portuguese links point at.
Isolation: only the two READMEs and the existence of the files they link are read; when the tests
run from a tree without them, such as an installed package, they are skipped.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


# The repository root: ``tests/unit/`` is two levels below it.
_ROOT = Path(__file__).resolve().parents[2]
# The two files the tests compare; they are skipped when either is missing from the tree.
_ENGLISH = _ROOT / "README.md"
_PORTUGUESE = _ROOT / "README.pt-BR.md"

# A Markdown link or image target: the text between "](" and the closing parenthesis.
_TARGET = re.compile(r"\]\(([^)\s]+)\)")

# An ATX heading; the run of "#" is its level.
_HEADING = re.compile(r"^(#{1,6}) ")

# Both READMEs are needed for every test below, so the mark is shared.
_needs_both = pytest.mark.skipif(
    not (_ENGLISH.is_file() and _PORTUGUESE.is_file()),
    reason="the two READMEs are not in this source tree",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _outside_fences(path: Path) -> list[str]:
    """
    Read a Markdown file and drop the lines inside fenced code blocks.

    Args:
        path (Path): The Markdown file.

    Returns:
        list[str]: The remaining lines, so that a ``#`` comment in a shell block is not a heading.
    """
    kept: list[str] = []
    fenced = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            fenced = not fenced
        elif not fenced:
            kept.append(line)
    return kept


def _commands(path: Path) -> list[str]:
    """
    List the command lines of the shell blocks of a README, in order.

    Args:
        path (Path): The Markdown file.

    Returns:
        list[str]: Every line inside a fence that is neither blank nor a ``#`` comment.
    """
    found: list[str] = []
    fenced = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            fenced = not fenced
        elif fenced and line.strip() and not line.lstrip().startswith("#"):
            found.append(line)
    return found


def _levels(path: Path) -> list[int]:
    """
    List the heading levels of a README, in order.

    Args:
        path (Path): The Markdown file.

    Returns:
        list[int]: One level (1 to 6) per heading.
    """
    found = (_HEADING.match(line) for line in _outside_fences(path))
    return [len(m.group(1)) for m in found if m]


def _table_rows(path: Path, header_start: str) -> int:
    """
    Count the data rows of the table whose header line starts with a given text.

    Args:
        path (Path): The Markdown file.
        header_start (str): The start of the header line, such as ``"| Milestone |"``.

    Returns:
        int: The rows under the header, not counting the header and its separator.
    """
    lines = _outside_fences(path)
    start = next(i for i, line in enumerate(lines) if line.startswith(header_start))
    rows = 0
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        rows += 1
    return rows


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@_needs_both
def test_both_readmes_have_the_same_headings_in_the_same_order() -> None:
    """The two files have one heading of the same level at each position."""
    assert _levels(_PORTUGUESE) == _levels(_ENGLISH)


@_needs_both
def test_both_readmes_have_the_same_comparison_rows() -> None:
    """The comparison with ZAP and Nuclei has the same rows in both."""
    assert _table_rows(_PORTUGUESE, "| | WebVigil |") == _table_rows(_ENGLISH, "| | WebVigil |")


@_needs_both
def test_both_readmes_have_the_same_milestone_rows() -> None:
    """Every milestone of the build is in both."""
    assert _table_rows(_PORTUGUESE, "| Marco |") == _table_rows(_ENGLISH, "| Milestone |")


@_needs_both
def test_both_readmes_have_the_same_shell_commands() -> None:
    """Commands are not translated, so a changed flag has to change in both files."""
    assert _commands(_PORTUGUESE) == _commands(_ENGLISH)


@_needs_both
def test_each_readme_links_to_the_other_in_its_first_lines() -> None:
    """The switch of language is below the title of each file."""
    english = "\n".join(_outside_fences(_ENGLISH)[:4])
    portuguese = "\n".join(_outside_fences(_PORTUGUESE)[:4])

    assert "README.pt-BR.md" in english
    assert "(README.md)" in portuguese


@_needs_both
def test_the_portuguese_readme_links_resolve_inside_the_repository() -> None:
    """Relative links work on GitHub only (PyPI shows README.md), so each must name a real file."""
    text = _PORTUGUESE.read_text(encoding="utf-8")
    relative = [t for t in _TARGET.findall(text) if not t.startswith(("https://", "#"))]
    srcset = re.findall(r'srcset="([^"]+)"|src="([^"]+)"', text)
    relative += [a or b for a, b in srcset if not (a or b).startswith("https://")]

    missing = [t for t in relative if not (_ROOT / t.split("#")[0]).exists()]

    assert relative
    assert missing == []
