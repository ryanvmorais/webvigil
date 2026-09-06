"""ScanRunner: queue, execution, cancellation, restart recovery — RF-09, RF-10, RF-14, RF-16."""

from __future__ import annotations

import asyncio
import functools
from collections.abc import AsyncIterator, Callable

import httpx
import pytest
from sqlalchemy import Engine
from sqlmodel import Session, select

from tests.fixtures.app import make_app
from tests.support import make_finding, make_result
from webvigil.api.db import Finding as FindingRow
from webvigil.api.db import Scan, ScanStatus
from webvigil.api.runner import ScanRunner, recover_interrupted_scans
from webvigil.core import InvalidTargetError, ScanConfig, ScanResult
from webvigil.core import orchestrator as orch_mod


class _FakeOrchestrator:
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
    return lambda _config: orch


def _new_scan(
    engine: Engine, *, target: str = "https://example.com/", options: dict | None = None
) -> int:
    with Session(engine) as session:
        scan = Scan(target=target, mode="passive", scope="host", options=options or {})
        session.add(scan)
        session.commit()
        assert scan.id is not None
        return scan.id


def _status(engine: Engine, scan_id: int) -> ScanStatus:
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None
        return ScanStatus(scan.status)


async def _wait_for(engine: Engine, scan_id: int, status: ScanStatus, timeout: float = 3.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if _status(engine, scan_id) == status:
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"scan {scan_id} is {_status(engine, scan_id)}, expected {status}")


@pytest.fixture
async def runner_factory(web_engine: Engine) -> AsyncIterator[Callable[..., object]]:
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
    orch = _FakeOrchestrator(result=make_result(make_finding()))
    runner = await runner_factory(orchestrator_factory=_factory(orch))
    scan_id = _new_scan(web_engine)
    runner.wake()

    await _wait_for(web_engine, scan_id, ScanStatus.COMPLETED)
    with Session(web_engine) as session:
        findings = session.exec(select(FindingRow).where(FindingRow.scan_id == scan_id)).all()
    assert len(findings) == 1


async def test_engine_error_marks_failed(web_engine: Engine, runner_factory: Callable) -> None:
    orch = _FakeOrchestrator(error=InvalidTargetError("bad target"))
    runner = await runner_factory(orchestrator_factory=_factory(orch))
    scan_id = _new_scan(web_engine)
    runner.wake()

    await _wait_for(web_engine, scan_id, ScanStatus.FAILED)
    with Session(web_engine) as session:
        assert "bad target" in (session.get(Scan, scan_id).error or "")


async def test_one_scan_runs_at_a_time(web_engine: Engine, runner_factory: Callable) -> None:
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
    gate = asyncio.Event()  # never set
    runner = await runner_factory(orchestrator_factory=_factory(_FakeOrchestrator(gate=gate)))
    scan_id = _new_scan(web_engine)
    runner.wake()
    await _wait_for(web_engine, scan_id, ScanStatus.RUNNING)

    assert await runner.cancel(scan_id) == "cancelled"
    await _wait_for(web_engine, scan_id, ScanStatus.CANCELLED)
    with Session(web_engine) as session:
        assert session.exec(select(FindingRow).where(FindingRow.scan_id == scan_id)).all() == []


async def test_cancel_a_queued_scan(web_engine: Engine, runner_factory: Callable) -> None:
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
