"""
The seams that raise, for the failure-injection suite of spec 027 (RF-02, RF-05, ADR-2).

The scan harness fails requests: :func:`attributed` names the running stage in a ``ContextVar``
while each pass of the table runs, and :class:`FaultTransport`, around the fixture's transport,
applies the fault plan of ``tests/failure/table.py`` to that stage's requests and records each
fault in a :class:`FaultLog`. The CLI harness fails a dependency: each helper patches one with
``monkeypatch`` and returns a :class:`Fault`, which records every exception it raised. Either
way a run checks that its faults really happened, so a stage the run never reached does not pass
(RF-05).
"""

from __future__ import annotations

import errno
import functools
import hashlib
import inspect
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import httpcore2
import httpx2
import pytest

from tests.failure.table import (
    STAGES,
    TARGET,
    Kind,
    failure_marker,
    failure_text,
    fault_for,
    stage,
)
from webvigil.core.orchestrator import Orchestrator
from webvigil.crawler.crawler import Crawler
from webvigil.http import addresses
from webvigil.reporting import _REPORTERS

# ---------------------------------------------------------------------------
# The scan harness: the stage of a request, and the faults the plan applies (ADR-2)
# ---------------------------------------------------------------------------

# The stage whose pass is running, which the fault transport reads. ``None`` outside every pass.
_STAGE: ContextVar[str | None] = ContextVar("failure_stage", default=None)

# The stage a request belongs to by its URL, whichever pass sends it.
_BY_URL: Final = "target"


@dataclass(frozen=True)
class Applied:
    """
    One fault the transport applied.

    Attributes:
        stage (str): The stage the request belonged to.
        kind (Kind): The kind applied.
        marker (str): The failure marker.
        url (str): The request's URL.
        attempt (int): The attempt, from 0.
        text (str): What the client got: the exception's text, or the response's body.
    """

    stage: str
    kind: Kind
    marker: str
    url: str
    attempt: int
    text: str


@dataclass
class FaultLog:
    """
    Every fault of one scan run, and how many requests each stage sent.

    Attributes:
        applied (list[Applied]): The faults, in order.
        requests (dict[str, int]): The requests each stage sent, attempts included.
    """

    applied: list[Applied] = field(default_factory=list)
    requests: dict[str, int] = field(default_factory=dict)

    def stages(self) -> set[str]:
        """
        Returns:
            set[str]: The stages that got at least one fault.
        """
        return {fault.stage for fault in self.applied}

    def kinds(self, name: str) -> set[Kind]:
        """
        Args:
            name (str): A stage's name.

        Returns:
            set[Kind]: The kinds that stage got.
        """
        return {fault.kind for fault in self.applied if fault.stage == name}


def _key(request: httpx2.Request) -> str:
    """
    Args:
        request (httpx2.Request): A request whose body has been read.

    Returns:
        str: What makes it the same request again: a retry repeats the method, the URL and the
            body.
    """
    digest = hashlib.sha256(request.content).hexdigest()
    return f"{request.method} {request.url} {digest}"


class FaultTransport(httpx2.AsyncBaseTransport):
    """
    A transport that applies the fault plan to the requests of the failing stages.

    A request whose URL is the target's belongs to the ``target`` stage; any other belongs to the
    stage :func:`attributed` names, or to ``stage_name`` when the transport has one. A request of
    a stage that does not fail in the run, or outside every stage, is forwarded as it is.
    """

    def __init__(
        self,
        inner: httpx2.AsyncBaseTransport,
        run: int,
        log: FaultLog,
        failing: frozenset[str],
        *,
        stage_name: str | None = None,
        json_body: bool = False,
    ) -> None:
        """
        Args:
            inner (httpx2.AsyncBaseTransport): What answers the requests that do not fail.
            run (int): The run number, from 0.
            log (FaultLog): Where each fault is recorded.
            failing (frozenset[str]): The stages that fail in this run.
            stage_name (str | None): The one stage of every request, for a client that only one
                pass uses. Defaults to the running stage.
            json_body (bool): Whether ``BAD_BODY`` is a ``200`` that is not JSON, for a client
                that reads JSON, instead of a ``gzip`` body that does not decode.
        """
        self._inner = inner
        self._run = run
        self._log = log
        self._failing = failing
        self._stage_name = stage_name
        self._json_body = json_body
        # per stage: each distinct request, in order, and how many times it was sent
        self._seen: dict[str, dict[str, int]] = {}

    def _stage_of(self, request: httpx2.Request) -> str | None:
        """
        Args:
            request (httpx2.Request): A request.

        Returns:
            str | None: Its stage, or ``None`` outside every stage.
        """
        if self._stage_name is not None:
            return self._stage_name
        if str(request.url) == TARGET:
            return _BY_URL
        return _STAGE.get()

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        """
        Args:
            request (httpx2.Request): The request the client sent.

        Returns:
            httpx2.Response: The inner transport's answer, or the fault's.

        Raises:
            httpx2.ConnectError: For ``REFUSED``.
            httpx2.ReadError: For ``RESET``.
            httpx2.ReadTimeout: For ``TIMEOUT``.
            RuntimeError: For ``RAISES``.
        """
        await request.aread()
        name = self._stage_of(request)
        if name is None:
            return await self._inner.handle_async_request(request)
        self._log.requests[name] = self._log.requests.get(name, 0) + 1
        if name not in self._failing:
            return await self._inner.handle_async_request(request)
        seen = self._seen.setdefault(name, {})
        key = _key(request)
        index = list(seen).index(key) if key in seen else len(seen)
        attempt = seen.get(key, 0)
        seen[key] = attempt + 1
        url = str(request.url)
        kind = fault_for(self._run, stage(name), index, url, attempt)
        if kind is None:
            return await self._inner.handle_async_request(request)
        marker = failure_marker(name, kind)
        text = failure_text(marker)
        self._log.applied.append(Applied(name, kind, marker, url, attempt, text))
        return self._apply(kind, marker, text, request)

    def _apply(
        self, kind: Kind, marker: str, text: str, request: httpx2.Request
    ) -> httpx2.Response:
        """
        Args:
            kind (Kind): The kind to apply.
            marker (str): Its marker, which a header can carry.
            text (str): The failure's text.
            request (httpx2.Request): The request that fails.

        Returns:
            httpx2.Response: The answer of ``SERVER_ERROR`` and ``BAD_BODY``.

        Raises:
            httpx2.ConnectError: For ``REFUSED``.
            httpx2.ReadError: For ``RESET``.
            httpx2.ReadTimeout: For ``TIMEOUT``.
            RuntimeError: For ``RAISES``.
        """
        body = text.encode("utf-8")
        if kind is Kind.REFUSED:
            raise httpx2.ConnectError(text, request=request)
        if kind is Kind.RESET:
            raise httpx2.ReadError(text, request=request)
        if kind is Kind.TIMEOUT:
            raise httpx2.ReadTimeout(text, request=request)
        if kind is Kind.RAISES:
            raise RuntimeError(text)
        if kind is Kind.SERVER_ERROR:
            # a header holds the marker only: the hostile text is not a valid header value
            headers = {"content-type": "text/html; charset=utf-8", "x-failure": marker}
            return httpx2.Response(503, headers=headers, stream=httpx2.ByteStream(body))
        if self._json_body:
            headers = {"content-type": "application/json"}
        else:
            headers = {"content-type": "text/html; charset=utf-8", "content-encoding": "gzip"}
        return httpx2.Response(200, headers=headers, stream=httpx2.ByteStream(body))


# The classes whose methods are the seams of the scan stages.
_OWNERS: Final[dict[str, type]] = {"Orchestrator": Orchestrator, "Crawler": Crawler}


def _named(name: str, method: Callable[..., Any]) -> Callable[..., Any]:
    """
    Args:
        name (str): A stage's name.
        method (Callable[..., Any]): The pass method of that stage.

    Returns:
        Callable[..., Any]: The same method, which names the stage while it runs.
    """
    if inspect.iscoroutinefunction(method):

        @functools.wraps(method)
        async def named_async(*args: Any, **kwargs: Any) -> Any:
            token = _STAGE.set(name)
            try:
                return await method(*args, **kwargs)
            finally:
                _STAGE.reset(token)

        return named_async

    @functools.wraps(method)
    def named(*args: Any, **kwargs: Any) -> Any:
        token = _STAGE.set(name)
        try:
            return method(*args, **kwargs)
        finally:
            _STAGE.reset(token)

    return named


@contextmanager
def attributed(owners: dict[str, type] | None = None) -> Iterator[None]:
    """
    Wrap the pass method of each scan stage of the table, so the running stage is named (ADR-2).

    Args:
        owners (dict[str, type] | None): The class each seam's prefix names. Defaults to the
            orchestrator and the crawler.

    Yields:
        None: While the block runs, each pass names its stage.

    Raises:
        AttributeError: If a seam names a method its class no longer has.
    """
    classes = _OWNERS if owners is None else owners
    patched: list[tuple[type, str, object]] = []
    try:
        for row in STAGES:
            if row.harness != "scan" or row.name == _BY_URL:
                continue
            owner_name, method_name = row.seam.split(".")
            owner = classes[owner_name]
            original = owner.__dict__.get(method_name)
            if original is None:
                raise AttributeError(f"{row.seam}: the seam of stage {row.name!r} is gone")
            patched.append((owner, method_name, original))
            setattr(owner, method_name, _named(row.name, getattr(owner, method_name)))
        yield
    finally:
        for owner, method_name, original in reversed(patched):
            setattr(owner, method_name, original)


def failing_osv(
    inner: httpx2.AsyncBaseTransport, run: int, log: FaultLog, failing: frozenset[str]
) -> FaultTransport:
    """
    Args:
        inner (httpx2.AsyncBaseTransport): The OSV.dev stub.
        run (int): The run number, from 0.
        log (FaultLog): Where each fault is recorded.
        failing (frozenset[str]): The stages that fail in this run.

    Returns:
        FaultTransport: The OSV client's transport, with the plan of the ``osv`` stage; its
            ``BAD_BODY`` is a ``200`` that is not JSON.
    """
    return FaultTransport(inner, run, log, failing, stage_name="osv", json_body=True)


# ---------------------------------------------------------------------------
# The CLI harness: seams that raise
# ---------------------------------------------------------------------------


@dataclass
class Fault:
    """
    What one seam raised.

    Attributes:
        marker (str): The marker its failures carry.
        raised (list[BaseException]): Every exception it raised, in order.
    """

    marker: str
    raised: list[BaseException] = field(default_factory=list)

    def fire(self, exc: BaseException) -> BaseException:
        """
        Record an exception about to be raised.

        Args:
            exc (BaseException): The exception, whose text holds the marker.

        Returns:
            BaseException: ``exc``, for the ``raise``.
        """
        self.raised.append(exc)
        return exc


def _same_file(a: object, b: Path) -> bool:
    """
    Args:
        a (object): The path a call was given.
        b (Path): The path the seam fails.

    Returns:
        bool: Whether both name the same file.
    """
    return Path(str(a)).resolve() == b.resolve()


def failing_resolver(monkeypatch: pytest.MonkeyPatch, marker: str) -> Fault:
    """
    Make the address guard's resolver raise for every name.

    Args:
        monkeypatch (pytest.MonkeyPatch): The test's patcher.
        marker (str): The failure's marker.

    Returns:
        Fault: What the resolver raised: ``httpcore2.ConnectError``, as the system resolver
            raises for a name that does not resolve.
    """
    fault = Fault(marker)

    async def _resolve(host: str, port: int) -> list[str]:
        raise fault.fire(httpcore2.ConnectError(failure_text(marker)))

    monkeypatch.setattr(addresses, "system_resolver", _resolve)
    return fault


def _io_error(fault: Fault) -> OSError:
    """
    Args:
        fault (Fault): The seam that raises it.

    Returns:
        OSError: An ``EIO`` whose text is the failure's, recorded on ``fault``.
    """
    exc = OSError(errno.EIO, failure_text(fault.marker))
    fault.fire(exc)
    return exc


def failing_read(monkeypatch: pytest.MonkeyPatch, path: Path, marker: str) -> Fault:
    """
    Make every read of one file raise ``OSError``; the file still exists and can be stat-ed.

    Args:
        monkeypatch (pytest.MonkeyPatch): The test's patcher.
        path (Path): The file whose reads fail.
        marker (str): The failure's marker.

    Returns:
        Fault: What the reads raised.
    """
    fault = Fault(marker)
    read_text = Path.read_text
    read_bytes = Path.read_bytes
    open_ = Path.open

    def _read_text(self: Path, *args: Any, **kwargs: Any) -> str:
        if _same_file(self, path):
            raise _io_error(fault)
        return read_text(self, *args, **kwargs)

    def _read_bytes(self: Path) -> bytes:
        if _same_file(self, path):
            raise _io_error(fault)
        return read_bytes(self)

    def _open(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if _same_file(self, path) and not any(flag in mode for flag in "wax+"):
            raise _io_error(fault)
        return open_(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _read_text)
    monkeypatch.setattr(Path, "read_bytes", _read_bytes)
    monkeypatch.setattr(Path, "open", _open)
    return fault


def failing_write(monkeypatch: pytest.MonkeyPatch, path: Path, marker: str) -> Fault:
    """
    Make every write of one file raise ``OSError``.

    Args:
        monkeypatch (pytest.MonkeyPatch): The test's patcher.
        path (Path): The file whose writes fail.
        marker (str): The failure's marker.

    Returns:
        Fault: What the writes raised.
    """
    fault = Fault(marker)
    write_text = Path.write_text
    write_bytes = Path.write_bytes
    open_ = Path.open

    def _write_text(self: Path, *args: Any, **kwargs: Any) -> int:
        if _same_file(self, path):
            raise _io_error(fault)
        return write_text(self, *args, **kwargs)

    def _write_bytes(self: Path, data: Any) -> int:
        if _same_file(self, path):
            raise _io_error(fault)
        return write_bytes(self, data)

    def _open(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if _same_file(self, path) and any(flag in mode for flag in "wax+"):
            raise _io_error(fault)
        return open_(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", _write_text)
    monkeypatch.setattr(Path, "write_bytes", _write_bytes)
    monkeypatch.setattr(Path, "open", _open)
    return fault


def failing_render(monkeypatch: pytest.MonkeyPatch, fmt: str, marker: str) -> Fault:
    """
    Make one reporter raise ``RuntimeError`` from ``render``.

    Args:
        monkeypatch (pytest.MonkeyPatch): The test's patcher.
        fmt (str): The report format whose reporter fails.
        marker (str): The failure's marker.

    Returns:
        Fault: What the reporter raised.
    """
    fault = Fault(marker)

    def _render(*_args: object, **_kwargs: object) -> str:
        raise fault.fire(RuntimeError(failure_text(marker)))

    render: Callable[..., str] = _render
    monkeypatch.setattr(_REPORTERS[fmt], "render", render)
    return fault
