"""
Reporters: JSON (canonical), SARIF 2.1.0, HTML (Jinja2), and Markdown.

Every reporter is a pure function of a
:class:`~webvigil.core.result.ScanResult`. JSON is lossless; :func:`load_result`
reloads it so ``webvigil report`` can re-render any format offline (RF-21,
RF-24).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError
from pydantic_core import ErrorDetails

from webvigil.core.bounded import truncate
from webvigil.core.findings import EvidenceItem, Finding, Location
from webvigil.core.result import CheckError, LoginSummary, ScanMetadata, ScanResult
from webvigil.core.technology import Technology
from webvigil.core.text import replace_surrogates_in
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
# How many places a refused report's message names, and the longest message it can quote. A
# damaged file can hold an error per field: the message must not grow with it.
_MAX_LOCATIONS_SHOWN = 3
_MAX_REASON_CHARS = 256
_NOT_JSON = "not a valid WebVigil report: the file is not valid JSON"
# The only names a refused report's message may repeat: a key of the file's own (a ``counts``
# entry, say) is the file's content, so it is left out of the path.
_REPORT_FIELDS = frozenset(
    name
    for model in (
        ScanResult,
        ScanMetadata,
        LoginSummary,
        Finding,
        Location,
        EvidenceItem,
        Technology,
        CheckError,
    )
    for name in model.model_fields
)


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
            report; the message counts the errors and names a few places, never a value
            from the file.
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
    return _parse_report(data)


def _parse_report(data: bytes) -> ScanResult:
    """
    Parse a report, reading an escaped unpaired surrogate as U+FFFD.

    Pydantic's JSON parser refuses such an escape outright, so a report holding one would be
    lost for a single character. Only a file it calls invalid JSON takes the slower way,
    through the standard parser, which reads the escape and leaves it to be replaced.

    Args:
        data (bytes): The file's content.

    Returns:
        ScanResult: The parsed result.

    Raises:
        ValueError: If the content is not a valid report, with the message
            :func:`load_result` documents.
    """
    try:
        return ScanResult.model_validate_json(data)
    except ValidationError as exc:
        # Only a lone error can be the JSON failure recovered from below.
        if exc.error_count() != 1:
            raise ValueError(_invalid_report(_error_details(exc))) from None
        details = _error_details(exc)
        if details[0]["type"] != "json_invalid":
            raise ValueError(_invalid_report(details)) from None
    except (ValueError, RecursionError):
        raise ValueError(_NOT_JSON) from None
    try:
        return ScanResult.model_validate(replace_surrogates_in(json.loads(data.decode("utf-8"))))
    except ValidationError as exc:
        raise ValueError(_invalid_report(_error_details(exc))) from None
    except (ValueError, RecursionError):
        raise ValueError(_NOT_JSON) from None


def _error_details(exc: ValidationError) -> list[ErrorDetails]:
    """
    Args:
        exc (ValidationError): Why a file did not load as a report.

    Returns:
        list[ErrorDetails]: Its errors, without the input, the context or a documentation URL.
    """
    return exc.errors(include_url=False, include_context=False, include_input=False)


def _invalid_report(details: list[ErrorDetails]) -> str:
    """
    Args:
        details (list[ErrorDetails]): The errors of a file that did not load as a report.

    Returns:
        str: A message of bounded size: the number of errors and the first few places, with
            no value from the file. A report from a newer WebVigil keeps its own message,
            which says to upgrade.
    """
    first = details[0]
    if len(details) == 1 and first["type"] == "value_error" and not first["loc"]:
        return truncate(first["msg"].removeprefix("Value error, "), _MAX_REASON_CHARS)
    places = list(dict.fromkeys(_field_path(detail["loc"]) for detail in details))
    shown = ", ".join(places[:_MAX_LOCATIONS_SHOWN])
    hidden = len(places) - _MAX_LOCATIONS_SHOWN
    more = f" and {hidden} more" if hidden > 0 else ""
    count = len(details)
    return (
        f"not a valid WebVigil report: {count} error{'' if count == 1 else 's'}, at {shown}{more}"
    )


def _field_path(location: tuple[int | str, ...]) -> str:
    """
    Args:
        location (tuple[int | str, ...]): Where a validation error happened.

    Returns:
        str: The path as ``findings[0].title``, made only of list positions and the names of
            the report's own fields, or ``"the top level"`` when none is left.
    """
    path = ""
    for part in location:
        if isinstance(part, int):
            path += f"[{part}]"
        elif part in _REPORT_FIELDS:
            path += f".{part}" if path else part
    return path or "the top level"


__all__ = ["MAX_REPORT_BYTES", "Reporter", "get_reporter", "load_result", "sort_findings"]
