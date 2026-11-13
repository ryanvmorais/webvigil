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

# The largest report file ``load_result`` reads. Parsing takes about one and a half times the
# file's size in memory on top of the text, so this keeps a file someone sent from exhausting the
# machine, while a real report (about 10 KiB per finding at worst) reaches it only with tens of
# thousands of findings.
MAX_REPORT_BYTES = 256 * 1024 * 1024


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

    Raises:
        OSError: If the file cannot be read.
        ValueError: If the file is larger than :data:`MAX_REPORT_BYTES`, or is not a valid
            report (a :class:`pydantic.ValidationError` is a ``ValueError``).
    """
    # Read one byte past the limit instead of trusting the size the file reports: a pipe or a
    # device has none, and a file can grow while it is read.
    with Path(path).open("rb") as handle:
        data = handle.read(MAX_REPORT_BYTES + 1)
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError(
            f"the file is larger than {MAX_REPORT_BYTES // (1024 * 1024)} MiB, the most "
            "`webvigil report` reads"
        )
    return ScanResult.model_validate_json(data)


__all__ = ["MAX_REPORT_BYTES", "Reporter", "get_reporter", "load_result", "sort_findings"]
