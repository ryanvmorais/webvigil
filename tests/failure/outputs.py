"""
Every output of a run, and the two searches over it (spec 027, RF-03, RF-04).

:class:`Outputs` holds each output a user or an operator can see, by name: ``stdout``,
``stderr``, ``report:<format>``, ``log``; the API harness adds its own. The part of a name before
the colon is its family, which :data:`ALLOWED` and :func:`bound_of` read.

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
        str: Its family: the part before the first colon.
    """
    return name.split(":", 1)[0]


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
    attribute, the traceback and any ``extra`` included.

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
        self.lines.append(f"{self.format(record)} {record.args!r} {vars(record)!r}")


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
    problems = [f"raw {match!r}" for match in sorted(set(_RAW_CONTROL_RE.findall(text)))]
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
