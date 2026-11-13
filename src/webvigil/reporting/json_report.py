r"""
The canonical JSON reporter (RF-21).

This format is lossless: ``webvigil.reporting.load_result`` is its exact inverse.

JSON escapes only the C0 controls, so DEL and the C1 range (which a terminal can read as the
start of an escape sequence) would be written raw into a report printed to standard output. They
are written as ``\u00XX`` escapes: the same string to a JSON parser, inert in a terminal.
"""

from __future__ import annotations

import re

from webvigil.core.result import ScanResult

# DEL and the C1 controls. They can only appear inside a JSON string (everything outside one is
# ASCII punctuation, digits and literals), where a ``\u00XX`` escape means the same character.
_RAW_CONTROL_RE = re.compile(r"[\x7f-\x9f]")


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
        return _RAW_CONTROL_RE.sub(
            lambda m: f"\\u{ord(m.group()):04x}", result.model_dump_json(indent=2)
        )
