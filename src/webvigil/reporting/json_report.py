"""The canonical JSON reporter (RF-21).

This format is lossless: ``webvigil.reporting.load_result`` is its exact inverse.
"""

from __future__ import annotations

from webvigil.core.result import ScanResult


class JsonReporter:
    fmt = "json"

    def render(self, result: ScanResult) -> str:
        return result.model_dump_json(indent=2)
