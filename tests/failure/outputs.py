"""
Every output of a run, and the two searches over it (spec 027, RF-03, RF-04).

:class:`Outputs` holds each output a user or an operator can see, by name: ``stdout``,
``stderr``, ``report:<format>``, ``log``; the API harness adds ``api-body:<route>``,
``api-header:<route>``, ``db:<table>`` and ``server-log``. The part of a name before the colon is
its family, which :data:`ALLOWED`, :data:`STORED` and :func:`bound_of` read.

:func:`credential_hits` must come back empty. :func:`failure_hits` names every output a failure
marker reached; each must be one its kind may reach, and there the text must be cut at its bound
with its controls shown as escapes.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import httpx2
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlmodel import SQLModel
from typer.testing import CliRunner, Result

from tests.failure.table import PAD_CHAR, Kind
from tests.support import spellings
from webvigil.cli import app as app_mod
from webvigil.core.bounded import TEXT_MAX_CHARS
from webvigil.core.output import TERMINAL_MAX_CHARS
from webvigil.core.text import INVISIBLE_CHARS

# Where the text of each kind of failure may appear, by output family. The body of a server error
# is site content, which a finding quotes as evidence (spec 025); a database failure's text goes
# to the server's log. Every other failure is named by its type, in the project's own words.
ALLOWED: Final[Mapping[Kind, frozenset[str]]] = {
    Kind.SERVER_ERROR: frozenset({"report", "api-body", "db"}),
    Kind.DB: frozenset({"server-log"}),
}

# The outputs that hold a value as it was stored: the database, and the JSON a client of the Web
# API reads. Each value there is bounded, and neutralized where it is shown (spec 025: the
# dashboard's ``showControls``), so only the bound is checked in them; JSON already escapes the C0
# controls.
STORED: Final = frozenset({"db", "api-body"})

# A raw control, bidirectional or zero-width character: tab and line feed are layout.
_RAW_CONTROL_RE: Final = re.compile(rf"[\x00-\x08\x0b-\x1f\x7f-\x9f{INVISIBLE_CHARS}]")
_PAD_RUN_RE: Final = re.compile(f"{re.escape(PAD_CHAR)}+")

# The formats a JSON report is re-rendered into, as a user would with `webvigil report`.
_RERENDERED: Final = ("sarif", "html", "md")

# The loggers whose records are an output of the project: the engine's and the Web API's, and the
# library loggers the Web API treats (``api/app.py``). Another package's logger, such as
# ``httpcore2``'s trace at ``DEBUG``, is left as its package configures it: the engine used as a
# library never changes another package's logger (spec 025, ADR-4), and neither the CLI nor the
# Web API turns it on.
OUTPUT_LOGGERS: Final = ("webvigil", "httpx2", "uvicorn.error")


def is_output_logger(name: str) -> bool:
    """
    Args:
        name (str): A logger's name.

    Returns:
        bool: Whether its records are an output of the project (:data:`OUTPUT_LOGGERS`).
    """
    return any(name == root or name.startswith(f"{root}.") for root in OUTPUT_LOGGERS)


def family(name: str) -> str:
    """
    Args:
        name (str): An output's name.

    Returns:
        str: Its family: the part before the first colon, without the number
            :meth:`Outputs.add` gives a second output of the same name (``log#2``).
    """
    return name.split(":", 1)[0].split("#", 1)[0]


def bound_of(name: str) -> int:
    """
    Args:
        name (str): An output's name.

    Returns:
        int: The longest run of a failure's padding the output may hold: the terminal's bound for
            the CLI's streams, the bound of ``Text`` elsewhere.
    """
    return TERMINAL_MAX_CHARS if family(name) in {"stdout", "stderr"} else TEXT_MAX_CHARS


@dataclass
class Outputs:
    """
    The outputs of one run, by name.

    Attributes:
        texts (dict[str, str]): Each output's text.
    """

    texts: dict[str, str] = field(default_factory=dict)

    def add(self, name: str, text: str) -> None:
        """
        Args:
            name (str): The output's name; a second output of the same name is numbered.
            text (str): Its text.
        """
        key, n = name, 2
        while key in self.texts:
            key, n = f"{name}#{n}", n + 1
        self.texts[key] = text


class LogLines(logging.Handler):
    """
    Keeps each record of :data:`OUTPUT_LOGGERS` as text: the message, its arguments and every
    attribute, the traceback and any ``extra`` included. The exception object itself is left out:
    every formatter writes ``exc_text``, which the project's log filter rebuilt from it, so the
    exception's own ``repr`` is never an output.

    Attributes:
        lines (list[str]): One entry per record, in the order they were emitted.
        other (int): The records of other loggers, which were left out.
    """

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
        self.lines: list[str] = []
        self.other = 0

    def emit(self, record: logging.LogRecord) -> None:
        """
        Args:
            record (logging.LogRecord): One record of any logger.
        """
        if not is_output_logger(record.name):
            self.other += 1
            return
        attributes = {key: value for key, value in vars(record).items() if key != "exc_info"}
        self.lines.append(f"{self.format(record)} {record.args!r} {attributes!r}")


@contextmanager
def every_log_record() -> Iterator[LogLines]:
    """
    Keep every record of the root logger at ``DEBUG`` while the block runs.

    Yields:
        LogLines: The handler, whose ``lines`` fill as the block runs.
    """
    handler = LogLines()
    root = logging.getLogger()
    level = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        yield handler
    finally:
        root.removeHandler(handler)
        root.setLevel(level)


# Wide enough that Rich never wraps an error line, so a test reads it whole.
WIDE_TERMINAL: Final = {"COLUMNS": "2000"}


def cli_outputs(runner: CliRunner, result: Result, report: Path, logs: LogLines) -> Outputs:
    """
    Collect every output of one CLI scan.

    Args:
        runner (CliRunner): The runner that ran it, which also re-renders the report.
        result (Result): The run.
        report (Path): Where the run was asked to write its JSON report.
        logs (LogLines): The records kept while it ran.

    Returns:
        Outputs: The standard output and error, the report, the same result in the three other
            formats through ``webvigil report`` when the report was written, and the log.
    """
    outputs = Outputs()
    outputs.add("stdout", result.stdout)
    outputs.add("stderr", result.stderr)
    if report.is_file():
        outputs.add(f"report:{report.suffix.lstrip('.')}", report.read_text("utf-8"))
        if report.suffix == ".json":
            for fmt in _RERENDERED:
                again = runner.invoke(
                    app_mod.app, ["report", str(report), "--format", fmt], env=WIDE_TERMINAL
                )
                outputs.add(f"report:{fmt}", again.stdout)
                outputs.add("stderr:report", again.stderr)
    for line in logs.lines:
        outputs.add("log", line)
    return outputs


# The report formats the Web API serves.
_API_FORMATS: Final = ("json", "sarif", "html", "md")


def _headers(response: httpx2.Response) -> str:
    """
    Args:
        response (httpx2.Response): A response of the Web API.

    Returns:
        str: Every header, one per line.
    """
    return "\n".join(f"{key}: {value}" for key, value in response.headers.multi_items())


def _response(outputs: Outputs, route: str, response: httpx2.Response) -> None:
    """
    Args:
        outputs (Outputs): Where the response goes.
        route (str): The route's name, after the family.
        response (httpx2.Response): The route's response.
    """
    outputs.add(f"api-header:{route}", _headers(response))
    outputs.add(f"api-body:{route}", response.text)


def api_outputs(client: TestClient, scan_id: int, engine: Engine, logs: LogLines) -> Outputs:
    """
    Collect every output of one scan the Web API ran.

    Args:
        client (TestClient): A client logged in to the API.
        scan_id (int): The scan.
        engine (Engine): An engine over the API's database.
        logs (LogLines): The records kept while it ran.

    Returns:
        Outputs: The body and headers of the scan, findings (every page), check-count and list
            routes; the four reports when the scan has results, each a ``report:<format>``
            output like the CLI's; every row of every table; the server log.
    """
    outputs = Outputs()
    scan = client.get(f"/api/scans/{scan_id}")
    _response(outputs, "scan", scan)
    cursor: str | None = None
    while True:
        params = {"limit": "200", **({"cursor": cursor} if cursor else {})}
        page = client.get(f"/api/scans/{scan_id}/findings", params=params)
        _response(outputs, "findings", page)
        cursor = page.json().get("next_cursor")
        if not cursor:
            break
    _response(outputs, "checks", client.get(f"/api/scans/{scan_id}/findings/checks"))
    _response(outputs, "list", client.get("/api/scans", params={"limit": "100"}))
    for fmt in _API_FORMATS:
        report = client.get(f"/api/scans/{scan_id}/report", params={"format": fmt})
        if report.status_code == 200:
            outputs.add(f"report:{fmt}", report.text)
            outputs.add(f"api-header:report-{fmt}", _headers(report))
        else:
            _response(outputs, f"report-{fmt}", report)
    with engine.connect() as connection:
        for table in SQLModel.metadata.sorted_tables:
            for row in connection.execute(table.select()):
                cells = " ".join(f"{column}={value}" for column, value in row._mapping.items())
                outputs.add(f"db:{table.name}", cells)
    for line in logs.lines:
        outputs.add("server-log", line)
    return outputs


@dataclass(frozen=True)
class Hit:
    """
    One place a marker was found.

    Attributes:
        output (str): The output's name.
        marker (str): The marker.
        form (str): The spelling that matched.
    """

    output: str
    marker: str
    form: str


def credential_hits(outputs: Outputs, markers: Iterable[str]) -> list[Hit]:
    """
    Args:
        outputs (Outputs): A run's outputs.
        markers (Iterable[str]): The run's credential markers.

    Returns:
        list[Hit]: Every output that holds a credential marker in any spelling of
            :func:`~tests.support.spellings`; a passing run has none (RF-03).
    """
    forms = [(marker, form) for marker in markers for form in sorted(spellings(marker))]
    return [
        Hit(name, marker, form)
        for name, text in outputs.texts.items()
        for marker, form in forms
        if form in text
    ]


@dataclass(frozen=True)
class FailureHit:
    """
    One output a failure marker reached.

    Attributes:
        output (str): The output's name.
        marker (str): The marker.
        allowed (bool): Whether the marker's kind may reach that output (RF-04).
        problems (tuple[str, ...]): What the output got wrong there: a raw control character, a
            padding run past its bound.
    """

    output: str
    marker: str
    allowed: bool
    problems: tuple[str, ...]


def _problems(name: str, text: str) -> tuple[str, ...]:
    """
    Args:
        name (str): An output's name.
        text (str): Its text.

    Returns:
        tuple[str, ...]: What breaks the rules of spec 025 there.
    """
    raw = set() if family(name) in STORED else set(_RAW_CONTROL_RE.findall(text))
    problems = [f"raw {match!r}" for match in sorted(raw)]
    longest = max((len(run) for run in _PAD_RUN_RE.findall(text)), default=0)
    if longest > bound_of(name):
        problems.append(f"a run of {longest} characters, past {bound_of(name)}")
    return tuple(problems)


def failure_hits(outputs: Outputs, markers: Mapping[str, Kind]) -> list[FailureHit]:
    """
    Args:
        outputs (Outputs): A run's outputs.
        markers (Mapping[str, Kind]): Each failure marker of the run, with its kind.

    Returns:
        list[FailureHit]: Every output a failure marker reached.
    """
    return [
        FailureHit(
            name,
            marker,
            family(name) in ALLOWED.get(kind, frozenset()),
            _problems(name, text),
        )
        for name, text in outputs.texts.items()
        for marker, kind in markers.items()
        if marker in text
    ]


def bad_failure_hits(outputs: Outputs, markers: Mapping[str, Kind]) -> list[FailureHit]:
    """
    Args:
        outputs (Outputs): A run's outputs.
        markers (Mapping[str, Kind]): Each failure marker of the run, with its kind.

    Returns:
        list[FailureHit]: The hits a passing run may not have: in an output the kind may not
            reach, or with a problem where it may.
    """
    return [hit for hit in failure_hits(outputs, markers) if not hit.allowed or hit.problems]
