"""
The seams that raise, for the failure-injection suite of spec 027 (RF-02, RF-05).

Each helper patches one dependency with ``monkeypatch`` and returns a :class:`Fault`, which
records every exception it raised: a run checks that its fault really happened, so a stage the
run never reached does not pass (RF-05).
"""

from __future__ import annotations

import errno
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpcore2
import pytest

from tests.failure.table import failure_text
from webvigil.http import addresses
from webvigil.reporting import _REPORTERS


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
