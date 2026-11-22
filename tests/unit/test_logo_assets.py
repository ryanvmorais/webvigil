"""
The WebVigil logo is one drawing in four files, and the four must stay the same drawing.

The path is written in the README asset, the dashboard's app icon, the dashboard's ``Logo``
component and the HTML report template. Isolation: the tests only read those four files from the
source tree (no render, no network). Every tree that holds ``tests/`` holds the four files too (a
clone or a source archive; the sdist and the wheel carry no tests), so a missing file is a failure:
a rename that the tests did not follow, never a reason to skip.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


# ``tests/unit/`` is two levels below the repository root.
_ROOT = Path(__file__).resolve().parents[2]
_ASSET = _ROOT / "assets" / "webvigil-web-vulnerability-scanner-logo.svg"
_ICON = _ROOT / "web" / "src" / "app" / "icon.svg"
_COMPONENT = _ROOT / "web" / "src" / "components" / "logo.tsx"
_TEMPLATE = _ROOT / "src" / "webvigil" / "reporting" / "templates" / "report.html.j2"
# The four files that hold the drawing, each checked for presence by name.
_FILES = (_ASSET, _ICON, _COMPONENT, _TEMPLATE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _path_of_svg(file: Path) -> str:
    """
    Read the ``d`` attribute of the logo path in a file that writes it as ``d="..."``.

    Args:
        file (Path): The SVG, or the template that holds the inline SVG.

    Returns:
        str: The path data.
    """
    found = re.search(r'fill-rule="evenodd"[^>]* d="([^"]+)"', file.read_text("utf-8"))
    assert found is not None, f"no logo path in {file.name}"
    return found.group(1)


def _path_of_component() -> str:
    """
    Join the string pieces of the ``PATH`` constant of ``logo.tsx``.

    Returns:
        str: The path data, as the component draws it.
    """
    source = _COMPONENT.read_text("utf-8")
    body = re.search(r"const PATH =(.*?);", source, re.DOTALL)
    assert body is not None, "no PATH constant in logo.tsx"
    return "".join(re.findall(r'"([^"]+)"', body.group(1)))


# ---------------------------------------------------------------------------
# One drawing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("file", _FILES, ids=lambda file: file.name)
def test_each_logo_file_is_where_the_tests_read_it(file: Path) -> None:
    """A moved or renamed file fails here by name, instead of skipping the comparison."""
    assert file.is_file(), f"{file.relative_to(_ROOT)} is missing: update the path in this test"


def test_the_four_files_draw_the_same_path() -> None:
    """The asset, the app icon, the component and the report template hold one path."""
    reference = _path_of_svg(_ASSET)

    assert _path_of_svg(_ICON) == reference
    assert _path_of_svg(_TEMPLATE) == reference
    assert _path_of_component() == reference


def test_the_asset_is_cropped_to_the_drawing() -> None:
    """The README aligns the logo to the baseline of the title, which needs no empty margin."""
    text = _ASSET.read_text("utf-8")

    assert 'viewBox="3 8 58 48"' in text
