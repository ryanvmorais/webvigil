"""
What the Web API logs about a failed scan is bounded, kept on its lines and free of stored values.

Two failures go through the real :class:`~webvigil.api.runner.ScanRunner` with a stand-in
orchestrator (no network), and logging is captured at ``DEBUG`` on the root logger:

- a scan whose engine raises with a message that holds an escape sequence, line breaks that
  imitate a record of their own and far more text than the bound: the record names the type and
  the frames, and the message is left out (spec 027);
- a scan whose result is stored into a database whose findings table was dropped, so SQLAlchemy
  raises with the failed statement, and would add its parameters (the finding's text) without
  ``hide_parameters``.

The last tests check that the app's lifespan gives the ``LOG`` profile to the library loggers
that can carry scan text (spec 025, ADR-4).
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable, Iterator
from typing import Any

import pytest
import sqlalchemy
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, text
from sqlmodel import Session

from tests.api.conftest import FakeOrchestrator
from tests.support import make_finding, make_result
from webvigil.api.app import create_app
from webvigil.api.config import WebConfig
from webvigil.api.db import Scan, ScanStatus, run_alembic_upgrade
from webvigil.api.runner import INTERNAL_ERROR, ScanRunner
from webvigil.core import ScanConfig, ScanResult
from webvigil.core.bounded import URL_MAX_CHARS
from webvigil.core.output import SafeLogFilter

# A raw control, bidirectional or zero-width character; a line feed is allowed, since a traceback
# keeps its own lines.
_RAW = re.compile(
    r"[\x00-\x09\x0b-\x1f\x7f-\x9f"
    r"\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
)
# A line that a hostile message would add if its line breaks were kept.
_FORGED = "ERROR webvigil.api scan 999 completed"
_HOSTILE_MESSAGE = f"engine broke\x1b[2J\n{_FORGED}\r\n\u202e" + "x" * (100 * 1024)
# A value only the stored finding holds: it may reach the log only as a statement parameter.
_CANARY = "canary-7f3e2a-finding-text"
# A handler's usual layout: the record's lines are counted on what a log file would hold.
_FORMAT = logging.Formatter("%(levelname)s %(name)s %(message)s")


class _Crashing:
    """Stands in for an engine that raises with a hostile message."""

    def __init__(self, _config: ScanConfig) -> None: ...

    async def run(self, _target: str) -> ScanResult:
        """
        Args:
            _target (str): The scan target.

        Returns:
            ScanResult: Never returned.

        Raises:
            RuntimeError: Always, with :data:`_HOSTILE_MESSAGE`.
        """
        raise RuntimeError(_HOSTILE_MESSAGE)


class _Finished:
    """Stands in for an engine whose result holds the canary in a finding."""

    def __init__(self, _config: ScanConfig) -> None: ...

    async def run(self, _target: str) -> ScanResult:
        """
        Args:
            _target (str): The scan target.

        Returns:
            ScanResult: One finding whose URL carries :data:`_CANARY`.
        """
        return make_result(make_finding(url=f"https://example.com/{_CANARY}"))


async def _run_one(engine: Engine, factory: Callable[[ScanConfig], Any]) -> tuple[int, Scan]:
    """
    Run one queued scan to its end.

    Args:
        engine (Engine): The database engine the runner uses.
        factory (Callable[[ScanConfig], Any]): Builds what runs the scan.

    Returns:
        tuple[int, Scan]: The scan id and its final row.
    """
    with Session(engine) as session:
        scan = Scan(target="https://example.com/", mode="passive", scope="host", options={})
        session.add(scan)
        session.commit()
        assert scan.id is not None
        scan_id = scan.id
    runner = ScanRunner(engine, orchestrator_factory=factory)
    await runner.start()
    try:
        runner.wake()
        for _ in range(2_000):
            with Session(engine) as session:
                row = session.get(Scan, scan_id)
                assert row is not None
                if row.status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                    session.expunge(row)
                    return scan_id, row
            await asyncio.sleep(0.005)
    finally:
        await runner.stop()
    raise AssertionError(f"scan {scan_id} did not finish")


def _drop_findings(engine: Engine) -> None:
    """
    Args:
        engine (Engine): The engine over the per-test database, whose findings table goes.
    """
    with engine.begin() as connection:
        connection.execute(text("PRAGMA foreign_keys=OFF"))
        connection.execute(text('DROP TABLE "finding"'))


def _records(caplog: pytest.LogCaptureFixture, message: str) -> list[logging.LogRecord]:
    """
    Args:
        caplog (pytest.LogCaptureFixture): The capture.
        message (str): The rendered message to look for.

    Returns:
        list[logging.LogRecord]: The captured records with that message.
    """
    return [record for record in caplog.records if record.getMessage() == message]


async def test_a_crash_is_logged_by_its_type_and_frames_without_its_message(
    web_engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """The record names the type and keeps the frames on their lines; the message is left out."""
    with caplog.at_level(logging.DEBUG):
        scan_id, row = await _run_one(web_engine, _Crashing)

    assert row.status == ScanStatus.FAILED and row.error == INTERNAL_ERROR
    # Positive control: the crash was logged, with its frames.
    (record,) = _records(caplog, f"scan {scan_id} failed (RuntimeError)")
    assert record.exc_info is None and record.exc_text
    formatted = _FORMAT.format(record)
    assert "engine broke" not in caplog.text and "x" * 100 not in caplog.text
    assert not _RAW.search(caplog.text)
    assert not any(line.startswith(_FORGED) for line in formatted.splitlines())
    assert len(record.exc_text) <= URL_MAX_CHARS
    # Each line of the record is a line Python wrote: the header, the frames of the stand-in
    # engine, and the type alone on the last line.
    lines = formatted.splitlines()
    assert lines[0] == f"ERROR webvigil.api scan {scan_id} failed (RuntimeError)"
    assert lines[1] == "Traceback (most recent call last):"
    assert any(line.startswith("  File ") and "test_log_canary.py" in line for line in lines)
    assert lines[-1] == "RuntimeError"


async def test_a_failed_store_logs_the_statement_without_its_parameters(
    web_engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """The database error names the statement; the finding's text stays out of the log."""
    _drop_findings(web_engine)
    with caplog.at_level(logging.DEBUG):
        scan_id, row = await _run_one(web_engine, _Finished)

    assert row.status == ScanStatus.FAILED and row.error == INTERNAL_ERROR
    # Positive control: the failure was logged, with the statement that failed.
    (record,) = _records(caplog, f"storing the result of scan {scan_id} failed")
    assert record.exc_text and "no such table: finding" in record.exc_text
    assert "SQL parameters hidden" in record.exc_text
    assert _CANARY not in caplog.text
    assert not _RAW.search(caplog.text)


async def test_an_engine_without_hidden_parameters_would_log_the_canary(
    web_config: WebConfig, web_engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """The control of the test above: the same failure, on a plain engine, carries the value."""
    _drop_findings(web_engine)
    plain = create_engine(f"sqlite:///{web_config.database_path}")
    try:
        with caplog.at_level(logging.DEBUG):
            scan_id, _row = await _run_one(plain, _Finished)
    finally:
        plain.dispose()

    (record,) = _records(caplog, f"storing the result of scan {scan_id} failed")
    assert record.exc_text and _CANARY in record.exc_text


def test_the_migration_engine_hides_parameters_too(
    web_config: WebConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The engine the migrations open is built with ``hide_parameters`` as well (ADR-5)."""
    built: list[Engine] = []
    real = sqlalchemy.engine_from_config

    def recording(*args: Any, **kwargs: Any) -> Engine:
        engine = real(*args, **kwargs)
        built.append(engine)
        return engine

    monkeypatch.setattr(sqlalchemy, "engine_from_config", recording)
    run_alembic_upgrade(web_config)

    # Positive control: the migrations did open their engine through this function.
    (engine,) = built
    assert engine.hide_parameters is True
    assert create_engine("sqlite://").hide_parameters is False  # not SQLAlchemy's default


# ---------------------------------------------------------------------------
# The library loggers
# ---------------------------------------------------------------------------

# The loggers the lifespan treats, as api/app.py names them: a logger dropped there fails here.
_LIBRARY_LOGGERS = ("uvicorn.error", "httpx2")


def _safe_filters(name: str) -> int:
    """
    Args:
        name (str): A logger name.

    Returns:
        int: How many :class:`SafeLogFilter` that logger holds.
    """
    return sum(isinstance(item, SafeLogFilter) for item in logging.getLogger(name).filters)


@pytest.fixture
def _untreated_library_loggers() -> Iterator[None]:
    """
    Take the filter off the library loggers for one test, and put it back afterwards.

    An earlier app in the same process has attached it already, and the test must see the
    lifespan attach it.

    Yields:
        None: While the library loggers hold no filter.
    """
    removed: list[tuple[logging.Logger, logging.Filter]] = []
    for name in _LIBRARY_LOGGERS:
        log = logging.getLogger(name)
        for item in list(log.filters):
            if isinstance(item, SafeLogFilter):
                log.removeFilter(item)
                removed.append((log, item))
    yield
    for log, item in removed:
        if not any(isinstance(other, SafeLogFilter) for other in log.filters):
            log.addFilter(item)


@pytest.mark.usefixtures("_untreated_library_loggers")
@pytest.mark.parametrize("name", _LIBRARY_LOGGERS)
def test_the_lifespan_treats_the_library_loggers_once(
    web_config: WebConfig, name: str, caplog: pytest.LogCaptureFixture
) -> None:
    """After start-up, a record on the library logger is on one line and shows its controls."""
    log = logging.getLogger(name)
    with caplog.at_level(logging.DEBUG, logger=name):
        level, handlers = log.level, list(log.handlers)
        # Positive control: before the lifespan runs, the record goes out raw.
        log.error("before %s", "a\x1b[2Jb\nc")
        assert _RAW.search(caplog.records[-1].getMessage())
        assert _safe_filters(name) == 0

        for _ in range(2):  # a second app in the same process adds no second filter
            with TestClient(create_app(web_config, orchestrator_factory=FakeOrchestrator)):
                pass
        assert _safe_filters(name) == 1
        assert (log.level, log.handlers) == (level, handlers)

        log.error("after %s", "a\x1b[2Jb\nc")
        assert caplog.records[-1].getMessage() == "after a\\x1b[2Jb\\x0ac"
