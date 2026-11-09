"""
Pin the text of the README terminal recording (an SVG) to its character grid.

``svg-term`` places each run of text at a column but lets the browser space the letters, and it
draws the box characters of a table (``│``, ``┏``, ``╇``...) as text, so the lines show gaps and
the corners do not meet. This script fixes both without touching a colour:

* every ``<text>`` gets a ``textLength`` of one cell per character, so any monospace font fills the
  same grid, and the fonts that match 0.6 em come first in the stack;
* every box character is taken out of its text and drawn as filled rectangles from the centre of
  its cell to the edges, with the fill of the text it replaces, so the lines are continuous.

Run it on the SVG that ``svg-term`` wrote (nothing is added to ``pyproject.toml``):

    npx svg-term-cli --in assets/cli-scan-demo.cast --out assets/cli-scan-demo.svg \
        --window --no-cursor --width 110 --height 44
    uv run python scripts/tidy-demo-svg.py assets/cli-scan-demo.svg
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


#: The fonts of the page, those closest to 0.6 em first; ``svg-term`` writes Monaco and Consolas.
FONT_STACK = (
    "SFMono-Regular,Menlo,'DejaVu Sans Mono','Liberation Mono','Cascadia Mono',Consolas,monospace"
)

#: The width of one column and the height of one row in the SVG's units. ``svg-term`` sets the
#: font size to 1.67, a glyph to 0.6 em and a line to 1.3 em.
CELL_WIDTH = 1.002
ROW_HEIGHT = 2.171

#: The thickness of a light and of a heavy line (one unit is ten pixels in the README image).
LIGHT, HEAVY = 0.12, 0.24

#: What each box character joins, as (left, right, up, down) with 0 for none, 1 for a light line and
#: 2 for a heavy one. These are the characters Rich draws a table with.
BOX: dict[str, tuple[int, int, int, int]] = {
    "─": (1, 1, 0, 0),
    "│": (0, 0, 1, 1),
    "━": (2, 2, 0, 0),
    "┃": (0, 0, 2, 2),
    "┌": (0, 1, 0, 1),
    "┐": (1, 0, 0, 1),
    "└": (0, 1, 1, 0),
    "┘": (1, 0, 1, 0),
    "├": (0, 1, 1, 1),
    "┤": (1, 0, 1, 1),
    "┬": (1, 1, 0, 1),
    "┴": (1, 1, 1, 0),
    "┼": (1, 1, 1, 1),
    "┏": (0, 2, 0, 2),
    "┓": (2, 0, 0, 2),
    "┗": (0, 2, 2, 0),
    "┛": (2, 0, 2, 0),
    "┣": (0, 2, 2, 2),
    "┫": (2, 0, 2, 2),
    "┳": (2, 2, 0, 2),
    "┻": (2, 2, 2, 0),
    "╋": (2, 2, 2, 2),
    "┡": (0, 2, 2, 1),
    "┩": (2, 0, 2, 1),
    "╇": (2, 2, 2, 1),
    "┍": (0, 2, 0, 1),
    "┑": (2, 0, 0, 1),
    "┝": (0, 2, 1, 1),
    "┥": (2, 0, 1, 1),
    "┯": (2, 2, 0, 1),
}

#: A text element with its attributes and its (already escaped) content.
TEXT = re.compile(r"<text([^>]*)>([^<]+)</text>")

#: The font-family attribute that ``svg-term`` puts on the group around every line.
FONT_FAMILY = re.compile(r'font-family="[^"]*"')

#: An attribute such as ``x="2.004"``, read from the start of a text element.
X_ATTRIBUTE = re.compile(r'\bx="([\d.]+)"')

#: One run of characters that are all box characters, or all are not.
RUN = re.compile("[" + "".join(BOX) + "]+|[^" + "".join(BOX) + "]+")


# ---------------------------------------------------------------------------
# Rewrite
# ---------------------------------------------------------------------------


def _number(value: float) -> str:
    """
    Format a coordinate with the precision of the SVG, without trailing zeros.

    Args:
        value (float): The coordinate.

    Returns:
        str: The coordinate as text.
    """
    return f"{value:.3f}".rstrip("0").rstrip(".") or "0"


def _rect(x: float, y: float, width: float, height: float, css_class: str) -> str:
    """
    Build one filled rectangle.

    Args:
        x (float): Left edge.
        y (float): Top edge.
        width (float): Width.
        height (float): Height.
        css_class (str): The class of the replaced text, which carries the fill.

    Returns:
        str: The ``<rect>`` element.
    """
    return (
        f'<rect x="{_number(x)}" y="{_number(y)}" width="{_number(width)}" '
        f'height="{_number(height)}" class="{css_class}"/>'
    )


def _draw(char: str, column: float, css_class: str) -> str:
    """
    Draw one box character as rectangles from the centre of its cell to its edges.

    Args:
        char (str): A key of ``BOX``.
        column (float): The left edge of the cell, in the SVG's units.
        css_class (str): The class of the replaced text.

    Returns:
        str: The rectangles of the arms that exist.
    """
    left, right, up, down = BOX[char]
    thickness = (0.0, LIGHT, HEAVY)
    # An arm stops half a line past the centre, so two arms of a corner leave no notch.
    across = max(thickness[up], thickness[down]) / 2
    along = max(thickness[left], thickness[right]) / 2
    center_x = column + CELL_WIDTH / 2
    center_y = ROW_HEIGHT / 2
    # A hair of overlap at the cell edges hides the seam that anti-aliasing leaves.
    bleed = 0.03
    parts = []
    if left:
        width = thickness[left]
        parts.append(
            _rect(
                column - bleed,
                center_y - width / 2,
                CELL_WIDTH / 2 + bleed + across,
                width,
                css_class,
            )
        )
    if right:
        width = thickness[right]
        parts.append(
            _rect(
                center_x - across,
                center_y - width / 2,
                CELL_WIDTH / 2 + bleed + across,
                width,
                css_class,
            )
        )
    if up:
        width = thickness[up]
        parts.append(
            _rect(center_x - width / 2, -bleed, width, ROW_HEIGHT / 2 + bleed + along, css_class)
        )
    if down:
        width = thickness[down]
        parts.append(
            _rect(
                center_x - width / 2,
                center_y - along,
                width,
                ROW_HEIGHT / 2 + bleed + along,
                css_class,
            )
        )
    return "".join(parts)


def _pin(match: re.Match[str]) -> str:
    """
    Pin one text element to the grid and draw its box characters.

    Args:
        match (re.Match[str]): A ``<text>`` element found by ``TEXT``.

    Returns:
        str: The element as text pinned to the grid, with rectangles in place of box characters.
    """
    attributes, content = match.groups()
    start = X_ATTRIBUTE.search(attributes)
    origin = float(start.group(1)) if start else 0.0
    css_class = re.search(r'class="([^"]*)"', attributes)
    text = html.unescape(content)
    pieces = []
    position = 0
    for run in RUN.finditer(text):
        piece = run.group()
        column = origin + position * CELL_WIDTH
        if piece[0] in BOX:
            drawn = "".join(
                _draw(char, column + offset * CELL_WIDTH, css_class.group(1) if css_class else "")
                for offset, char in enumerate(piece)
            )
            pieces.append(drawn)
        else:
            moved = X_ATTRIBUTE.sub("", attributes)
            moved = f' x="{_number(column)}"' + moved
            length = _number(len(piece) * CELL_WIDTH)
            escaped = html.escape(piece, quote=False)
            pieces.append(
                f'<text{moved} textLength="{length}" lengthAdjust="spacing">{escaped}</text>'
            )
        position += len(piece)
    return "".join(pieces)


def tidy(svg: str) -> str:
    """
    Pin every text run of the SVG to the grid, draw its box characters and replace its fonts.

    Args:
        svg (str): The SVG written by ``svg-term``.

    Returns:
        str: The SVG with the fixed spacing and lines.
    """
    svg = FONT_FAMILY.sub(f'font-family="{FONT_STACK}"', svg)
    return TEXT.sub(_pin, svg)


def main() -> None:
    """Rewrite the SVG named on the command line in place."""
    path = Path(sys.argv[1])
    path.write_text(tidy(path.read_text(encoding="utf-8")), encoding="utf-8", newline="\n")
    print(f"tidied {path}")


if __name__ == "__main__":
    main()
