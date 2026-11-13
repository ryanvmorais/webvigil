r"""
Making the control and invisible characters in text from the scanned site visible.

A finding's title, location and evidence carry what the site sent: a cookie name, a header
value, a form field name, a response body. Printed to a terminal as they are, the control
characters among them (ESC, the C1 range, a lone carriage return) are acted on instead of shown:
they move the cursor, erase lines or change the window title. Every output that can reach a
terminal writes them as a visible ``\xNN`` escape instead, so it shows what the site sent.

The bidirectional controls and the zero-width characters do the same to whoever reads the text,
in a terminal or a browser: an override reverses what follows it and a zero-width space hides
inside a name, so a title, a URL or a piece of evidence reads differently from what it holds
(the "Trojan Source" characters). They are written as a visible ``\uNNNN`` escape.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# The bidirectional marks, embeddings, overrides and isolates (U+061C, U+200E-U+200F,
# U+202A-U+202E, U+2066-U+2069) and the invisible characters a name can hide (U+200B-U+200D,
# U+2060-U+2064, U+FEFF), as the body of a regex character class (the JSON reporter shares it).
# Kept in step with `web/src/lib/text.ts`.
INVISIBLE_CHARS = r"\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff"
# The C0 controls except tab and line feed, DEL and the C1 range. Tab and line feed are layout,
# and a carriage return is only kept as part of a CRLF pair (normalised to LF first).
_CONTROL_RE = re.compile(rf"[\x00-\x08\x0b-\x1f\x7f-\x9f{INVISIBLE_CHARS}]")
# On one line, the tab and the line feed are escaped too: a line break in a title would let the
# site print a line of its own under the scanner's.
_ONE_LINE_CONTROL_RE = re.compile(rf"[\x00-\x1f\x7f-\x9f{INVISIBLE_CHARS}]")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def show_controls(value: str, *, one_line: bool = False) -> str:
    r"""
    Args:
        value (str): Text that may have come from the scanned site.
        one_line (bool): Whether the text must stay on one line, so tabs and line feeds are
            escaped too. Defaults to ``False``.

    Returns:
        str: ``value`` with every control character written as ``\xNN`` and every
            bidirectional or invisible one as ``\uNNNN``; CRLF becomes LF first, so a body with
            Windows line endings reads as it did.
    """
    if one_line:
        return _ONE_LINE_CONTROL_RE.sub(_escape, value)
    return _CONTROL_RE.sub(_escape, value.replace("\r\n", "\n"))


def _escape(match: re.Match[str]) -> str:
    r"""
    Args:
        match (re.Match[str]): One control, bidirectional or invisible character.

    Returns:
        str: The character as a visible ``\xNN`` (up to U+00FF) or ``\uNNNN`` escape.
    """
    code = ord(match.group())
    return f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}"
