"""
Reporters: JSON (canonical), SARIF 2.1.0, HTML (Jinja2), and Markdown.

Every reporter is a pure function of a
:class:`~webvigil.core.result.ScanResult`. JSON is lossless; :func:`load_result`
reloads it so ``webvigil report`` can re-render any format offline (RF-21,
RF-24).
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from webvigil.core.result import ScanResult
from webvigil.reporting._ordering import sort_findings
from webvigil.reporting.html import HtmlReporter
from webvigil.reporting.json_report import JsonReporter
from webvigil.reporting.markdown import MarkdownReporter
from webvigil.reporting.sarif import SarifReporter


class Reporter(Protocol):
    """
    Renders a scan result into one text format.

    Attributes:
        fmt (str): The format key (``"json"``, ``"sarif"``, ``"html"``,
            ``"md"``) this reporter is registered under.
    """

    fmt: str

    def render(self, result: ScanResult) -> str:
        """
        Args:
            result (ScanResult): The scan result to render.

        Returns:
            str: The rendered report.
        """
        ...


_REPORTERS: dict[str, Reporter] = {
    reporter.fmt: reporter
    for reporter in (JsonReporter(), SarifReporter(), HtmlReporter(), MarkdownReporter())
}


def get_reporter(fmt: str) -> Reporter:
    """
    Args:
        fmt (str): A format key.

    Returns:
        Reporter: The matching reporter.

    Raises:
        ValueError: When ``fmt`` is not a known format.
    """
    try:
        return _REPORTERS[fmt]
    except KeyError:
        raise ValueError(f"unknown report format: {fmt!r}") from None


def load_result(path: str | Path) -> ScanResult:
    """
    Reload a canonical JSON report from disk — the exact inverse of the JSON reporter.

    Args:
        path (str | Path): Path to a JSON report.

    Returns:
        ScanResult: The parsed result.
    """
    return ScanResult.model_validate_json(Path(path).read_text("utf-8"))


__all__ = ["Reporter", "get_reporter", "load_result", "sort_findings"]
