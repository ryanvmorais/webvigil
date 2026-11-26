r"""
Making the control and invisible characters in text from the scanned site visible.

A finding's title, location and evidence carry what the site sent: a cookie name, a header
value, a form field name, a response body. Printed to a terminal as they are, the control
characters among them (ESC, the C1 range, a lone carriage return) are acted on instead of shown:
they move the cursor, erase lines or change the window title. Every output that can reach a
terminal writes them as a visible ``\xNN`` escape instead, so it shows what the site sent.

The bidirectional controls and the invisible characters do the same to whoever reads the text,
in a terminal or a browser: an override reverses what follows it, a zero-width space or a tag
character hides inside a name and a line separator breaks a line where a viewer shows none, so
a title, a URL or a piece of evidence reads differently from what it holds (the "Trojan Source"
characters and their kin). They are written as a visible ``\uNNNN`` escape, or ``\UNNNNNNNN``
past U+FFFF.

An unpaired surrogate is a different problem: a Python string can hold one, but UTF-8 cannot
encode it, so a single one in a page makes every later write of that text fail. It is replaced
where the text enters the engine (:func:`replace_surrogates`).
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# The bidirectional marks, embeddings, overrides and isolates (U+061C, U+200E-U+200F,
# U+202A-U+202E, U+2066-U+2069); the invisible characters a name can hide (U+200B-U+200D,
# U+2060-U+2064, U+FEFF), and those that show as nothing in most fonts: the soft hyphen (U+00AD),
# the combining grapheme joiner (U+034F), the Hangul fillers (U+115F, U+1160, U+3164, U+FFA0),
# the Khmer inherent vowels (U+17B4, U+17B5), the Mongolian vowel separator (U+180E), the
# interlinear annotation characters (U+FFF9-U+FFFB) and the tag characters (U+E0000-U+E007F);
# and the line and paragraph separators (U+2028, U+2029), a line break to some viewers and none
# to others. As the body of a regex character class (the JSON escape and the link rule share it).
# Kept in step with `web/src/lib/text.ts`.
INVISIBLE_CHARS = (
    r"\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2064"
    r"\u2066-\u2069\u3164\ufeff\uffa0\ufff9-\ufffb\U000e0000-\U000e007f"
)
# The C0 controls except tab and line feed, DEL and the C1 range. Tab and line feed are layout,
# and a carriage return is only kept as part of a CRLF pair (normalised to LF first).
_CONTROL_RE = re.compile(rf"[\x00-\x08\x0b-\x1f\x7f-\x9f{INVISIBLE_CHARS}]")
# On one line, the tab and the line feed are escaped too: a line break in a title would let the
# site print a line of its own under the scanner's.
_ONE_LINE_CONTROL_RE = re.compile(rf"[\x00-\x1f\x7f-\x9f{INVISIBLE_CHARS}]")
# DEL, the C1 controls and the bidirectional and invisible characters, as a JSON encoder writes
# them raw. JSON escapes only the C0 controls, and these can only appear inside a JSON string
# (everything outside one is ASCII punctuation, digits and literals), where a ``\uNNNN`` escape
# means the same character.
_JSON_RAW_CONTROL_RE = re.compile(rf"[\x7f-\x9f{INVISIBLE_CHARS}]")
# A surrogate code point on its own. A decoder or a JSON parser joins a valid pair into one
# character, so whatever is left here has no partner.
_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")
# What Unicode reserves for a character that could not be represented.
_REPLACEMENT_CHAR = "\ufffd"


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
            bidirectional or invisible one as ``\uNNNN`` (``\xNN`` up to U+00FF,
            ``\UNNNNNNNN`` past U+FFFF); CRLF becomes LF first, so a body with Windows line
            endings reads as it did.
    """
    if one_line:
        return _ONE_LINE_CONTROL_RE.sub(_escape, value)
    return _CONTROL_RE.sub(_escape, value.replace("\r\n", "\n"))


def escape_json_controls(document: str) -> str:
    r"""
    Escape what a JSON encoder writes raw from a JSON document.

    Args:
        document (str): An encoded JSON document, as ``json.dumps`` or pydantic writes it.

    Returns:
        str: ``document`` with DEL, the C1 controls and the bidirectional and invisible
            characters written as ``\uNNNN`` escapes (a surrogate pair of them past U+FFFF, as
            JSON writes such a character): the same document to a JSON parser, inert in a
            terminal and read as it holds.
    """
    return _JSON_RAW_CONTROL_RE.sub(_json_escape, document)


def replace_surrogates(value: str) -> str:
    """
    Args:
        value (str): Text that may have come from the scanned site or from a file.

    Returns:
        str: ``value`` with every unpaired surrogate replaced by U+FFFD, one for one, so its
            length does not change and the result always encodes to UTF-8.
    """
    if value.isascii():  # nearly every value, and the check costs nothing
        return value
    return _SURROGATE_RE.sub(_REPLACEMENT_CHAR, value)


def replace_surrogates_in(document: Any) -> Any:
    """
    Replace the unpaired surrogates of a parsed JSON document, keys included.

    An escape in a JSON document can parse into one, so a document from the scanned site can
    hold them in any string. The walk uses an explicit stack: how deep the document nests is the
    site's.

    Args:
        document (Any): A value returned by :func:`json.loads`; its lists and objects are
            changed in place.

    Returns:
        Any: The same document, or a new string when ``document`` is one.
    """
    if isinstance(document, str):
        return replace_surrogates(document)
    stack = [document]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in list(node.items()):
                clean = replace_surrogates(key)
                if clean != key:
                    del node[key]
                node[clean] = replace_surrogates(value) if isinstance(value, str) else value
                if isinstance(value, dict | list):
                    stack.append(value)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                if isinstance(value, str):
                    node[index] = replace_surrogates(value)
                elif isinstance(value, dict | list):
                    stack.append(value)
    return document


def _escape(match: re.Match[str]) -> str:
    r"""
    Args:
        match (re.Match[str]): One control, bidirectional or invisible character.

    Returns:
        str: The character as a visible ``\xNN`` (up to U+00FF), ``\uNNNN`` or, past U+FFFF,
            ``\UNNNNNNNN`` escape, as Python writes them: four digits after ``\u`` always end the
            escape.
    """
    code = ord(match.group())
    if code <= 0xFF:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"


def _json_escape(match: re.Match[str]) -> str:
    r"""
    Escape one character that a JSON encoder writes raw.

    Args:
        match (re.Match[str]): One character a JSON encoder writes raw.

    Returns:
        str: The character as a JSON ``\uNNNN`` escape, or past U+FFFF as the escapes of its
            UTF-16 surrogate pair, the only form JSON has for it.
    """
    code = ord(match.group())
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    high, low = divmod(code - 0x10000, 0x400)
    return f"\\u{0xD800 + high:04x}\\u{0xDC00 + low:04x}"
