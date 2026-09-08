"""
The canonical JSON reporter (RF-21).

This format is lossless: ``webvigil.reporting.load_result`` is its exact inverse.
"""

from __future__ import annotations

from webvigil.core.result import ScanResult


class JsonReporter:
    """Serialises the whole :class:`~webvigil.core.result.ScanResult` as indented JSON."""

    fmt = "json"

    def render(self, result: ScanResult) -> str:
        """
        Args:
            result (ScanResult): The scan result.

        Returns:
            str: The result as pretty-printed JSON, byte-for-byte reloadable.
        """
        return result.model_dump_json(indent=2)
