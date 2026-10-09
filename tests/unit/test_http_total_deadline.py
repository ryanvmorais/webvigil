"""
The total read deadline of the HTTP client (``[http] total_timeout_s``) — issue #140.

``timeout_s`` limits each connect, read and write on its own, so a server that sends one byte every
few seconds never trips it and can hold a request, and a concurrency slot, open for a very long
time. Every request goes through ``pytest-httpx``; the dripping body is a stream that sleeps
between bytes, each pause far under the per-read timeout (15 s here) and the sum over the deadline
(0.2 s). The retry backoff is zeroed, as in the other client tests, so the retries do not sleep.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import httpx
import pytest

from webvigil.core.config import ScanConfig
from webvigil.core.errors import RequestFailed
from webvigil.core.target import Target
from webvigil.http import client as client_mod
from webvigil.http.client import HttpClient

_URL = "https://example.com/"
_DEADLINE = 0.2


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero the retry backoff so the retry tests do not actually sleep."""
    monkeypatch.setattr(client_mod, "BACKOFF_BASE_S", 0.0)
    monkeypatch.setattr(client_mod, "BACKOFF_JITTER_S", 0.0)


def _client(total: float = _DEADLINE) -> HttpClient:
    """
    Args:
        total (float): The ``[http] total_timeout_s`` value. Defaults to ``_DEADLINE``.

    Returns:
        HttpClient: A client for ``https://example.com`` with that total deadline.
    """
    config = ScanConfig.model_validate({"http": {"total_timeout_s": total}})
    return HttpClient(Target.parse("https://example.com"), config)


class _Drip(httpx.AsyncByteStream):
    """A response body of ``count`` single bytes, ``pause`` seconds apart; pulls are counted."""

    def __init__(self, count: int, pause: float = 0.05) -> None:
        self._count = count
        self._pause = pause
        self.pulled = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for _ in range(self._count):
            await asyncio.sleep(self._pause)
            self.pulled += 1
            yield b"x"


async def test_a_dripping_body_is_cut_off_by_the_total_deadline(httpx_mock: object) -> None:
    """No single read is slow, but the whole body outlasts the deadline: the request fails."""
    streams: list[_Drip] = []

    def respond(request: httpx.Request) -> httpx.Response:
        streams.append(_Drip(count=1000))  # 50 s of dripping, against a 0.2 s deadline
        return httpx.Response(200, stream=streams[-1])

    httpx_mock.add_callback(respond, is_reusable=True)  # type: ignore[attr-defined]
    async with _client() as http:
        with pytest.raises(RequestFailed, match="total_timeout_s"):
            await http.get(_URL)
    # An idempotent request is retried like any timeout (three attempts), then reported.
    assert (http.stats.requests, http.stats.retries, http.stats.failed) == (3, 2, 1)
    # Each attempt stopped pulling at the deadline instead of draining the stream.
    assert all(stream.pulled < 10 for stream in streams)


async def test_a_post_is_not_retried_after_the_deadline(httpx_mock: object) -> None:
    """A non-idempotent request is never re-sent after a timeout, the deadline included."""
    httpx_mock.add_callback(  # type: ignore[attr-defined]
        lambda request: httpx.Response(200, stream=_Drip(count=1000))
    )
    async with _client() as http:
        with pytest.raises(RequestFailed, match="total_timeout_s"):
            await http.request("POST", _URL, data={"a": "b"})
    assert (http.stats.requests, http.stats.retries, http.stats.failed) == (1, 0, 1)


async def test_a_slow_response_inside_the_deadline_is_untouched(httpx_mock: object) -> None:
    """A body that takes a while but finishes in time is read whole, with nothing counted."""
    httpx_mock.add_callback(  # type: ignore[attr-defined]
        lambda request: httpx.Response(200, stream=_Drip(count=3, pause=0.02))
    )
    async with _client(total=5.0) as http:
        response = await http.get(_URL)
    assert response.content == b"xxx"
    assert (http.stats.retries, http.stats.failed) == (0, 0)


async def test_the_deadline_does_not_count_the_wait_for_a_slot(httpx_mock: object) -> None:
    """A request queued behind another for the one slot gets its own full deadline."""
    httpx_mock.add_callback(  # type: ignore[attr-defined]
        lambda request: httpx.Response(200, stream=_Drip(count=4, pause=0.1)),
        is_reusable=True,
    )
    config = ScanConfig.model_validate(
        {"http": {"concurrency": 1, "total_timeout_s": 0.6}},
    )
    async with HttpClient(Target.parse("https://example.com"), config) as http:
        # Each takes ~0.4 s, inside the 0.6 s deadline. The second waits ~0.4 s for the slot, so
        # it would run ~0.8 s on its own clock and fail if the wait counted.
        first, second = await asyncio.gather(http.get(_URL), http.get(_URL))
    assert first.content == second.content == b"xxxx"
    assert http.stats.failed == 0


def test_the_deadline_has_a_default_and_must_be_positive() -> None:
    """A minute by default, and ``0`` (which would fail every request) is a configuration error."""
    assert ScanConfig().http.total_timeout_s == 60.0
    with pytest.raises(ValueError):
        ScanConfig.model_validate({"http": {"total_timeout_s": 0}})
