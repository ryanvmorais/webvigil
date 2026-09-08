"""
The single-slot scan runner: one background task, one scan at a time (RF-09, RF-10, RF-14).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Literal, Protocol

from sqlalchemy import Engine
from sqlmodel import Session, select

from webvigil.api.db import TERMINAL_STATUSES, Scan, ScanStatus, utcnow
from webvigil.api.mapping import build_scan_config, store_result
from webvigil.core import Orchestrator, ScanConfig, ScanResult, WebVigilError

logger = logging.getLogger("webvigil.api")

# The two outcomes of a cancel request.
type CancelOutcome = Literal["cancelled", "not_cancellable"]


class _OrchestratorLike(Protocol):
    """The one method the runner needs from an orchestrator — a test seam."""

    async def run(self, raw_target: str) -> ScanResult:
        """
        Args:
            raw_target (str): The target URL.

        Returns:
            ScanResult: The completed scan.
        """
        ...


OrchestratorFactory = Callable[[ScanConfig], _OrchestratorLike]


def _default_orchestrator(config: ScanConfig) -> _OrchestratorLike:
    """
    Args:
        config (ScanConfig): The engine configuration.

    Returns:
        _OrchestratorLike: A real :class:`~webvigil.core.orchestrator.Orchestrator`.
    """
    return Orchestrator(config)


class ScanRunner:
    """Owns the one execution slot. Created and driven by the app lifespan."""

    def __init__(
        self,
        engine: Engine,
        *,
        orchestrator_factory: OrchestratorFactory = _default_orchestrator,
    ) -> None:
        """
        Args:
            engine (Engine): The DB engine; every DB helper opens its own
                short-lived session on it.
            orchestrator_factory (OrchestratorFactory): Builds the object whose
                ``run`` executes a scan. Overridden in tests; defaults to the
                real orchestrator.
        """
        self._engine = engine
        self._make_orchestrator = orchestrator_factory
        self._event = asyncio.Event()
        self._loop_task: asyncio.Task[None] | None = None
        self._current: tuple[int, asyncio.Task[None]] | None = None
        self._stopped = False

    async def start(self) -> None:
        """Start the background dispatch loop (called from the app lifespan)."""
        self._stopped = False
        self._loop_task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        """Signal the loop to stop, cancel any running scan, and await the loop task."""
        self._stopped = True
        self._event.set()
        if self._current is not None:
            self._current[1].cancel()
        if self._loop_task is not None:
            await self._loop_task

    def wake(self) -> None:
        """Nudge the loop to re-check the queue — call after enqueueing a scan."""
        self._event.set()

    def _should_stop(self) -> bool:
        """
        Returns:
            bool: The stop flag. A method call, not a bare attribute read, so
                mypy does not narrow it across ``await`` points where a
                concurrent :meth:`stop` may have flipped it.
        """
        return self._stopped

    @property
    def current_scan_id(self) -> int | None:
        """
        Returns:
            int | None: The id of the scan executing right now, or ``None``.
        """
        return self._current[0] if self._current is not None else None

    async def cancel(self, scan_id: int) -> CancelOutcome:
        """
        Cancel a scan, whether it is running or still queued.

        Args:
            scan_id (int): The scan to cancel.

        Returns:
            CancelOutcome: ``"cancelled"`` when the running task was cancelled
                or a queued row was moved to ``CANCELLED``; ``"not_cancellable"``
                when the scan is neither.
        """
        if self._current is not None and self._current[0] == scan_id:
            self._current[1].cancel()
            return "cancelled"
        if await asyncio.to_thread(self._cancel_queued, scan_id):
            return "cancelled"
        return "not_cancellable"

    # -- background loop -------------------------------------------------------

    async def _loop(self) -> None:
        """
        The dispatch loop: claim the next queued scan, run it, repeat; sleep when idle.

        A running scan cancelled mid-flight is marked ``CANCELLED``. Runs until
        :meth:`stop` sets the flag and wakes it.
        """
        while not self._should_stop():
            scan_id = await asyncio.to_thread(self._claim_next_queued)
            if scan_id is None:
                self._event.clear()
                if self._should_stop():
                    return
                await self._event.wait()
                continue
            task = asyncio.create_task(self._run_scan(scan_id))
            self._current = (scan_id, task)
            try:
                await task
            except asyncio.CancelledError:
                await asyncio.to_thread(self._mark_cancelled, scan_id)
            finally:
                self._current = None

    async def _run_scan(self, scan_id: int) -> None:
        """
        Execute one scan: load its config, run the orchestrator, store or fail.

        A :class:`~webvigil.core.errors.WebVigilError` becomes a ``FAILED`` row
        with its message; any other exception is logged and becomes a
        ``FAILED`` row with a generic message; ``CancelledError`` propagates to
        the loop.

        Args:
            scan_id (int): The scan to run.
        """
        target, config = await asyncio.to_thread(self._load_config, scan_id)
        try:
            result = await self._make_orchestrator(config).run(target)
        except asyncio.CancelledError:
            raise
        except WebVigilError as exc:
            await asyncio.to_thread(self._terminate, scan_id, ScanStatus.FAILED, str(exc))
            return
        except Exception as exc:
            logger.exception("scan %s crashed", scan_id)
            await asyncio.to_thread(
                self._terminate, scan_id, ScanStatus.FAILED, f"internal error: {exc!r}"
            )
            return
        await asyncio.to_thread(self._store, scan_id, result)

    # -- DB helpers (each opens its own short-lived session) -------------------

    def _claim_next_queued(self) -> int | None:
        """
        Atomically move the oldest ``QUEUED`` scan to ``RUNNING`` and return its id.

        Returns:
            int | None: The claimed scan id, or ``None`` when the queue is
                empty.
        """
        with Session(self._engine) as session:
            scan = session.exec(
                select(Scan)
                .where(Scan.status == ScanStatus.QUEUED)
                .order_by(Scan.created_at, Scan.id)  # type: ignore[arg-type]
            ).first()
            if scan is None:
                return None
            scan.status = ScanStatus.RUNNING
            scan.started_at = utcnow()
            session.add(scan)
            session.commit()
            return scan.id

    def _load_config(self, scan_id: int) -> tuple[str, ScanConfig]:
        """
        Args:
            scan_id (int): The scan to load.

        Returns:
            tuple[str, ScanConfig]: Its target and the engine config built from
                the row.

        Raises:
            LookupError: If the row has disappeared.
        """
        with Session(self._engine) as session:
            scan = session.get(Scan, scan_id)
            if scan is None:  # pragma: no cover
                raise LookupError(f"scan {scan_id} disappeared")
            return scan.target, build_scan_config(scan)

    def _store(self, scan_id: int, result: ScanResult) -> None:
        """Persist a completed scan's result (see :func:`~webvigil.api.mapping.store_result`)."""
        with Session(self._engine) as session:
            store_result(session, scan_id, result)

    def _cancel_queued(self, scan_id: int) -> bool:
        """
        Args:
            scan_id (int): The scan to cancel.

        Returns:
            bool: ``True`` when the scan was ``QUEUED`` and is now ``CANCELLED``.
        """
        return self._terminate(scan_id, ScanStatus.CANCELLED, None, only_from=ScanStatus.QUEUED)

    def _mark_cancelled(self, scan_id: int) -> None:
        """Move a scan cancelled mid-run to ``CANCELLED``."""
        self._terminate(scan_id, ScanStatus.CANCELLED, None)

    def _terminate(
        self,
        scan_id: int,
        status: ScanStatus,
        error: str | None,
        *,
        only_from: ScanStatus | None = None,
    ) -> bool:
        """
        Move a non-terminal scan to a terminal state, stamping ``finished_at``.

        Args:
            scan_id (int): The scan to terminate.
            status (ScanStatus): The terminal status to set.
            error (str | None): The failure message, if any.
            only_from (ScanStatus | None): Require the current status to equal
                this, else do nothing.

        Returns:
            bool: ``True`` when the transition was applied.
        """
        with Session(self._engine) as session:
            scan = session.get(Scan, scan_id)
            if scan is None or scan.status in TERMINAL_STATUSES:
                return False
            if only_from is not None and scan.status != only_from:
                return False
            scan.status = status
            scan.error = error
            scan.finished_at = utcnow()
            session.add(scan)
            session.commit()
            return True


def recover_interrupted_scans(engine: Engine) -> int:
    """
    Mark scans left ``RUNNING`` by a dead process as ``INTERRUPTED`` (RF-16).

    Called once on startup, before the runner loop begins.

    Args:
        engine (Engine): The DB engine.

    Returns:
        int: How many scans were recovered.
    """
    with Session(engine) as session:
        stuck = session.exec(select(Scan).where(Scan.status == ScanStatus.RUNNING)).all()
        for scan in stuck:
            scan.status = ScanStatus.INTERRUPTED
            scan.error = "server restarted during scan"
            scan.finished_at = utcnow()
            session.add(scan)
        session.commit()
        return len(stuck)
