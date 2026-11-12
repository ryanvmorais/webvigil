"""
ScanRunner: queue, execution, cancellation, restart recovery — RF-09, RF-10, RF-14, RF-16.

Most tests drive a real :class:`ScanRunner` over the per-test DB with a
``_FakeOrchestrator`` whose ``run`` can hang on an ``asyncio.Event`` (to hold a
scan RUNNING), raise (to test failure), or return a canned result. ``_wait_for``
polls the scan row's status. The last test swaps in the real orchestrator
pointed at the in-process fixture app.
"""

from __future__ import annotations

import asyncio
import functools
import threading
import time
from collections.abc import AsyncIterator, Callable

import httpx
import pytest
from sqlalchemy import Engine
from sqlmodel import Session, select

from tests.fixtures.app import make_app
from tests.support import make_finding, make_result
from webvigil.api import runner as runner_mod
from webvigil.api.db import Finding as FindingRow
from webvigil.api.db import Scan, ScanStatus
from webvigil.api.runner import INTERNAL_ERROR, ScanRunner, recover_interrupted_scans
from webvigil.core import InvalidTargetError, ScanConfig, ScanResult
from webvigil.core import orchestrator as orch_mod


class _FakeOrchestrator:
    """
    A stand-in orchestrator: ``run`` optionally waits on ``gate``, then raises
    ``error`` or returns ``result``.
    """

    def __init__(
        self,
        *,
        result: ScanResult | None = None,
        error: Exception | None = None,
        gate: asyncio.Event | None = None,
    ) -> None:
        self._result = result if result is not None else make_result()
        self._error = error
        self._gate = gate

    async def run(self, raw_target: str) -> ScanResult:
        if self._gate is not None:
            await self._gate.wait()
        if self._error is not None:
            raise self._error
        return self._result


def _factory(orch: _FakeOrchestrator) -> Callable[[ScanConfig], _FakeOrchestrator]:
    """
    Args:
        orch (_FakeOrchestrator): The orchestrator every config should resolve to.

    Returns:
        Callable[[ScanConfig], _FakeOrchestrator]: An orchestrator factory that
            ignores its config and always returns ``orch``.
    """
    return lambda _config: orch


def _new_scan(
    engine: Engine, *, target: str = "https://example.com/", options: dict | None = None
) -> int:
    """
    Args:
        engine (Engine): The per-test database engine.
        target (str): The scan target column value.
        options (dict | None): The scan options JSON.

    Returns:
        int: The id of the inserted QUEUED scan row.
    """
    with Session(engine) as session:
        scan = Scan(target=target, mode="passive", scope="host", options=options or {})
        session.add(scan)
        session.commit()
        assert scan.id is not None
        return scan.id


def _status(engine: Engine, scan_id: int) -> ScanStatus:
    """
    Args:
        engine (Engine): The per-test database engine.
        scan_id (int): The scan row id.

    Returns:
        ScanStatus: The scan's current status.
    """
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None
        return ScanStatus(scan.status)


async def _wait_for(engine: Engine, scan_id: int, status: ScanStatus, timeout: float = 3.0) -> None:
    """
    Poll until scan ``scan_id`` reaches ``status``, or fail after ``timeout`` seconds.

    Args:
        engine (Engine): The per-test database engine.
        scan_id (int): The scan row id.
        status (ScanStatus): The status to wait for.
        timeout (float): Seconds to wait before giving up.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if _status(engine, scan_id) == status:
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"scan {scan_id} is {_status(engine, scan_id)}, expected {status}")


@pytest.fixture
async def runner_factory(web_engine: Engine) -> AsyncIterator[Callable[..., object]]:
    """Yield a coroutine that builds and starts a :class:`ScanRunner`, stopping each on teardown."""
    started: list[ScanRunner] = []

    async def _make(**kwargs: object) -> ScanRunner:
        runner = ScanRunner(web_engine, **kwargs)  # type: ignore[arg-type]
        await runner.start()
        started.append(runner)
        return runner

    yield _make
    for runner in started:
        await runner.stop()


async def test_queued_scan_runs_to_completed(web_engine: Engine, runner_factory: Callable) -> None:
    """A queued scan is picked up, runs, and its findings are written."""
    orch = _FakeOrchestrator(result=make_result(make_finding()))
    runner = await runner_factory(orchestrator_factory=_factory(orch))
    scan_id = _new_scan(web_engine)
    runner.wake()

    await _wait_for(web_engine, scan_id, ScanStatus.COMPLETED)
    with Session(web_engine) as session:
        findings = session.exec(select(FindingRow).where(FindingRow.scan_id == scan_id)).all()
    assert len(findings) == 1


async def test_a_wake_up_during_an_empty_claim_is_not_lost(
    web_engine: Engine, runner_factory: Callable, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    A scan enqueued right after the claim saw an empty queue still runs.

    The race: the dispatch loop looks at the queue and finds it empty; a scan is enqueued and
    ``wake()`` is called; only then does the loop go to sleep. The loop used to clear the event
    after the claim, which erased that wake-up and left the scan QUEUED until the next one was
    created (the intermittent ``scan N is queued`` failure of ``test_scans.py`` in CI).
    """
    real_start_next = ScanRunner._start_next
    raced: dict[str, int] = {}

    async def start_next_then_race(self: ScanRunner):  # type: ignore[no-untyped-def]
        started = await real_start_next(self)
        if started is None and not raced:
            raced["id"] = _new_scan(web_engine)  # enqueued right after the empty claim ...
            self.wake()  # ... and the API nudges the runner
        return started

    monkeypatch.setattr(ScanRunner, "_start_next", start_next_then_race)
    await runner_factory(orchestrator_factory=_factory(_FakeOrchestrator()))
    while "id" not in raced:
        await asyncio.sleep(0.01)

    await _wait_for(web_engine, raced["id"], ScanStatus.COMPLETED)


async def test_engine_error_marks_failed(web_engine: Engine, runner_factory: Callable) -> None:
    """An engine error marks the scan FAILED with the error message recorded."""
    orch = _FakeOrchestrator(error=InvalidTargetError("bad target"))
    runner = await runner_factory(orchestrator_factory=_factory(orch))
    scan_id = _new_scan(web_engine)
    runner.wake()

    await _wait_for(web_engine, scan_id, ScanStatus.FAILED)
    with Session(web_engine) as session:
        assert "bad target" in (session.get(Scan, scan_id).error or "")


async def test_one_scan_runs_at_a_time(web_engine: Engine, runner_factory: Callable) -> None:
    """With two scans queued, the second stays QUEUED until the first finishes."""
    gate = asyncio.Event()
    runner = await runner_factory(orchestrator_factory=_factory(_FakeOrchestrator(gate=gate)))
    first = _new_scan(web_engine)
    second = _new_scan(web_engine)
    runner.wake()

    await _wait_for(web_engine, first, ScanStatus.RUNNING)
    assert _status(web_engine, second) == ScanStatus.QUEUED

    gate.set()
    await _wait_for(web_engine, first, ScanStatus.COMPLETED)
    await _wait_for(web_engine, second, ScanStatus.COMPLETED)


async def test_cancel_a_running_scan(web_engine: Engine, runner_factory: Callable) -> None:
    """Cancelling a RUNNING scan stops it, marks it CANCELLED, and writes no findings."""
    gate = asyncio.Event()  # never set
    runner = await runner_factory(orchestrator_factory=_factory(_FakeOrchestrator(gate=gate)))
    scan_id = _new_scan(web_engine)
    runner.wake()
    await _wait_for(web_engine, scan_id, ScanStatus.RUNNING)

    assert await runner.cancel(scan_id) == "cancelled"
    await _wait_for(web_engine, scan_id, ScanStatus.CANCELLED)
    with Session(web_engine) as session:
        assert session.exec(select(FindingRow).where(FindingRow.scan_id == scan_id)).all() == []


def _widen_claim_gap(monkeypatch: pytest.MonkeyPatch, delay: float = 0.3) -> None:
    """
    Hold every claim open for ``delay`` seconds after its DB commit.

    The runner marks a scan RUNNING on a worker thread and only then, back on the event
    loop, registers it as the current scan. The sleep stretches that gap from a few
    milliseconds to ``delay``, so the tests below land in it every time instead of now
    and then (issue #89).

    Args:
        monkeypatch (pytest.MonkeyPatch): Patches ``ScanRunner._claim_next_queued``.
        delay (float): Seconds the worker thread sleeps after the commit.
    """
    original = ScanRunner._claim_next_queued

    def slow(self: ScanRunner) -> int | None:
        scan_id = original(self)
        if scan_id is not None:
            time.sleep(delay)
        return scan_id

    monkeypatch.setattr(ScanRunner, "_claim_next_queued", slow)


async def test_cancel_right_after_the_claim_is_not_missed(
    web_engine: Engine, runner_factory: Callable, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A scan that is RUNNING in the DB is cancellable even before the runner registers it."""
    _widen_claim_gap(monkeypatch)
    gate = asyncio.Event()  # only a cancel should end this scan
    runner = await runner_factory(orchestrator_factory=_factory(_FakeOrchestrator(gate=gate)))
    scan_id = _new_scan(web_engine)
    runner.wake()
    await _wait_for(web_engine, scan_id, ScanStatus.RUNNING)

    try:
        assert await runner.cancel(scan_id) == "cancelled"
        await _wait_for(web_engine, scan_id, ScanStatus.CANCELLED)
    finally:
        gate.set()  # lets a scan that was not cancelled end, so a failure does not hang


async def test_stop_right_after_the_claim_cancels_the_scan(
    web_engine: Engine, runner_factory: Callable, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``stop()`` in the claim gap still cancels the new scan instead of waiting it out."""
    _widen_claim_gap(monkeypatch)
    gate = asyncio.Event()  # never set: only a cancel can end this scan
    runner = await runner_factory(orchestrator_factory=_factory(_FakeOrchestrator(gate=gate)))
    scan_id = _new_scan(web_engine)
    runner.wake()
    await _wait_for(web_engine, scan_id, ScanStatus.RUNNING)

    # Not ``wait_for(runner.stop())``: its timeout cancels ``stop()``, which cancels the loop
    # task and would mark the scan CANCELLED by accident, hiding a ``stop()`` that hangs.
    stopping = asyncio.create_task(runner.stop())
    try:
        done, _pending = await asyncio.wait({stopping}, timeout=3.0)
        assert stopping in done, "stop() waited for the whole scan instead of cancelling it"
        assert _status(web_engine, scan_id) == ScanStatus.CANCELLED
    finally:
        gate.set()  # lets a scan that was not cancelled end, so a failure does not hang
        await stopping


async def test_cancel_a_queued_scan(web_engine: Engine, runner_factory: Callable) -> None:
    """Cancelling a QUEUED scan marks it CANCELLED without ever running it."""
    gate = asyncio.Event()
    runner = await runner_factory(orchestrator_factory=_factory(_FakeOrchestrator(gate=gate)))
    running = _new_scan(web_engine)
    queued = _new_scan(web_engine)
    runner.wake()
    await _wait_for(web_engine, running, ScanStatus.RUNNING)

    assert await runner.cancel(queued) == "cancelled"
    assert _status(web_engine, queued) == ScanStatus.CANCELLED
    gate.set()


async def test_recover_interrupted_scans(web_engine: Engine) -> None:
    """On restart, a scan left RUNNING from a previous process is marked INTERRUPTED."""
    with Session(web_engine) as session:
        scan = Scan(
            target="https://x.test/", mode="passive", scope="host", status=ScanStatus.RUNNING
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id
    assert recover_interrupted_scans(web_engine) == 1
    assert _status(web_engine, scan_id) == ScanStatus.INTERRUPTED  # type: ignore[arg-type]


async def test_runner_drives_the_real_engine(
    web_engine: Engine, runner_factory: Callable, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the real orchestrator against the fixture app, a scan produces real findings."""
    transport = httpx.ASGITransport(app=make_app("insecure"))
    monkeypatch.setattr(
        orch_mod, "HttpClient", functools.partial(orch_mod.HttpClient, transport=transport)
    )
    runner = await runner_factory()  # default (real) orchestrator factory
    scan_id = _new_scan(
        web_engine, target="http://demo.test/", options={"disabled_checks": ["tls.https"]}
    )
    runner.wake()

    await _wait_for(web_engine, scan_id, ScanStatus.COMPLETED, timeout=10.0)
    with Session(web_engine) as session:
        findings = session.exec(select(FindingRow).where(FindingRow.scan_id == scan_id)).all()
    assert {f.check_id for f in findings} >= {"http.headers.csp", "http.cookies.flags"}


# ---------------------------------------------------------------------------
# Unexpected errors: recorded generically, and the loop carries on
# ---------------------------------------------------------------------------


def _error(engine: Engine, scan_id: int) -> str | None:
    """
    Read the error a scan row recorded.

    Args:
        engine (Engine): The per-test database engine.
        scan_id (int): The scan row id.

    Returns:
        str | None: The error recorded on the scan.
    """
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None
        return scan.error


async def test_a_crash_records_a_generic_error(
    web_engine: Engine, runner_factory: Callable
) -> None:
    """The exception text stays in the log; the scan row says only ``internal error``."""
    orch = _FakeOrchestrator(error=RuntimeError("/srv/private/path leaked"))
    runner = await runner_factory(orchestrator_factory=_factory(orch))
    scan_id = _new_scan(web_engine)
    runner.wake()

    await _wait_for(web_engine, scan_id, ScanStatus.FAILED)
    assert _error(web_engine, scan_id) == INTERNAL_ERROR


async def test_a_config_that_cannot_be_loaded_fails_the_scan_not_the_loop(
    web_engine: Engine, runner_factory: Callable, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A row the runner cannot turn into a config is FAILED, and the next scan still runs."""
    real_load = ScanRunner._load_config
    broken: set[int] = set()

    def load(self: ScanRunner, scan_id: int) -> tuple[str, ScanConfig]:
        if scan_id in broken:
            raise RuntimeError("unreadable options")
        return real_load(self, scan_id)

    monkeypatch.setattr(ScanRunner, "_load_config", load)
    runner = await runner_factory(orchestrator_factory=_factory(_FakeOrchestrator()))
    first = _new_scan(web_engine)
    broken.add(first)
    second = _new_scan(web_engine)
    runner.wake()

    await _wait_for(web_engine, first, ScanStatus.FAILED)
    assert _error(web_engine, first) == INTERNAL_ERROR
    await _wait_for(web_engine, second, ScanStatus.COMPLETED)


async def test_a_failed_claim_does_not_stop_the_loop(
    web_engine: Engine, runner_factory: Callable, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The database failing one claim used to end the loop and leave every later scan QUEUED."""
    monkeypatch.setattr(runner_mod, "_RETRY_AFTER_ERROR_S", 0.01)
    real_claim = ScanRunner._claim_next_queued
    failures = {"left": 1}

    def claim(self: ScanRunner) -> int | None:
        if failures["left"]:
            failures["left"] -= 1
            raise RuntimeError("database is locked")
        return real_claim(self)

    monkeypatch.setattr(ScanRunner, "_claim_next_queued", claim)
    scan_id = _new_scan(web_engine)
    await runner_factory(orchestrator_factory=_factory(_FakeOrchestrator()))

    await _wait_for(web_engine, scan_id, ScanStatus.COMPLETED)


async def test_a_failed_store_fails_the_scan_and_the_next_one_runs(
    web_engine: Engine, runner_factory: Callable, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A write that fails leaves the scan FAILED, not RUNNING forever."""
    real_store = ScanRunner._store
    failures = {"left": 1}

    def store(self: ScanRunner, scan_id: int, result: ScanResult) -> None:
        if failures["left"]:
            failures["left"] -= 1
            raise RuntimeError("disk full")
        real_store(self, scan_id, result)

    monkeypatch.setattr(ScanRunner, "_store", store)
    runner = await runner_factory(orchestrator_factory=_factory(_FakeOrchestrator()))
    first = _new_scan(web_engine)
    second = _new_scan(web_engine)
    runner.wake()

    await _wait_for(web_engine, first, ScanStatus.FAILED)
    assert _error(web_engine, first) == INTERNAL_ERROR
    await _wait_for(web_engine, second, ScanStatus.COMPLETED)


# ---------------------------------------------------------------------------
# A cancel or a stop while the result is being stored
# ---------------------------------------------------------------------------


def _slow_store(monkeypatch: pytest.MonkeyPatch, delay: float = 0.3) -> threading.Event:
    """
    Hold every store open for ``delay`` seconds before it writes.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patches ``ScanRunner._store``.
        delay (float): Seconds the worker thread sleeps before writing.

    Returns:
        threading.Event: Set when a store has started, so the test acts inside the write.
    """
    real_store = ScanRunner._store
    started = threading.Event()

    def store(self: ScanRunner, scan_id: int, result: ScanResult) -> None:
        started.set()
        time.sleep(delay)
        real_store(self, scan_id, result)

    monkeypatch.setattr(ScanRunner, "_store", store)
    return started


async def test_a_cancel_during_the_store_is_refused(
    web_engine: Engine, runner_factory: Callable, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The result is in: the scan ends COMPLETED with its findings, never CANCELLED with them."""
    storing = _slow_store(monkeypatch)
    orch = _FakeOrchestrator(result=make_result(make_finding()))
    runner = await runner_factory(orchestrator_factory=_factory(orch))
    scan_id = _new_scan(web_engine)
    runner.wake()
    assert await asyncio.to_thread(storing.wait, 3.0)

    assert await runner.cancel(scan_id) == "not_cancellable"
    await _wait_for(web_engine, scan_id, ScanStatus.COMPLETED)
    with Session(web_engine) as session:
        findings = session.exec(select(FindingRow).where(FindingRow.scan_id == scan_id)).all()
    assert len(findings) == 1


async def test_a_stop_during_the_store_lets_the_write_finish(
    web_engine: Engine, runner_factory: Callable, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``stop()`` waits for the write instead of cancelling a scan whose result is in."""
    storing = _slow_store(monkeypatch)
    runner = await runner_factory(orchestrator_factory=_factory(_FakeOrchestrator()))
    scan_id = _new_scan(web_engine)
    runner.wake()
    assert await asyncio.to_thread(storing.wait, 3.0)

    await runner.stop()
    assert _status(web_engine, scan_id) == ScanStatus.COMPLETED
