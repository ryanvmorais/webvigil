r"""
Making the control characters in text from the scanned site visible.

A finding's title, location and evidence carry what the site sent: a cookie name, a header
value, a form field name, a response body. Printed to a terminal as they are, the control
characters among them (ESC, the C1 range, a lone carriage return) are acted on instead of shown:
they move the cursor, erase lines or change the window title. Every output that can reach a
terminal writes them as a visible ``\xNN`` escape instead, so it shows what the site sent.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# The C0 controls except tab and line feed, DEL and the C1 range. Tab and line feed are layout,
# and a carriage return is only kept as part of a CRLF pair (normalised to LF first).
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
# On one line, the tab and the line feed are escaped too: a line break in a title would let the
# site print a line of its own under the scanner's.
_ONE_LINE_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


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
        str: ``value`` with every control character written as ``\xNN``; CRLF becomes LF
            first, so a body with Windows line endings reads as it did.
    """
    if one_line:
        return _ONE_LINE_CONTROL_RE.sub(_escape, value)
    return _CONTROL_RE.sub(_escape, value.replace("\r\n", "\n"))


def _escape(match: re.Match[str]) -> str:
    r"""
    Args:
        match (re.Match[str]): One control character.

    Returns:
        str: The character as a visible ``\xNN`` escape.
    """
    return f"\\x{ord(match.group()):02x}"
