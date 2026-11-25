r"""
The canonical JSON reporter (RF-21).

This format is lossless: ``webvigil.reporting.load_result`` is its exact inverse.

JSON escapes only the C0 controls, so DEL and the C1 range (which a terminal can read as the
start of an escape sequence) would be written raw into a report printed to standard output. They
are written as ``\u00XX`` escapes: the same string to a JSON parser, inert in a terminal. The
bidirectional and invisible characters (:data:`webvigil.core.text.INVISIBLE_CHARS`), which make a
value read differently from what it holds, are written as ``\uNNNN`` escapes the same way
(:func:`webvigil.core.text.escape_json_controls`).
"""

from __future__ import annotations

from webvigil.core.result import ScanResult
from webvigil.core.text import escape_json_controls


class JsonReporter:
    """Serialises the whole :class:`~webvigil.core.result.ScanResult` as indented JSON."""

    fmt = "json"

    def render(self, result: ScanResult) -> str:
        """
        Args:
            result (ScanResult): The scan result.

        Returns:
            str: The result as pretty-printed JSON, byte-for-byte reloadable, with no raw
                control character.
        """
        return escape_json_controls(result.model_dump_json(indent=2))
