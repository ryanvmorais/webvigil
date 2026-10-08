"""
The response-body limit of the HTTP client (``[http] max_body_bytes``) — security audit, 1.0.0.

A scanner reads responses from servers it does not control. Without a limit, ``httpx`` loads
the whole body into memory: a hostile server, a multi-gigabyte file reached by a probe or a
compressed body that inflates a thousandfold can exhaust the scanner. All requests go through
``pytest-httpx``; the endless-stream test counts how much the client actually pulled.
"""

from __future__ import annotations

import gzip
from collections.abc import AsyncIterator

import httpx
import pytest

from webvigil.core.config import ScanConfig
from webvigil.core.target import Target
from webvigil.http.client import HttpClient, HttpStats, truncated_warning

_LIMIT = 1000
_URL = "https://example.com/"


def _client(limit: int = _LIMIT) -> HttpClient:
    """
    Args:
        limit (int): The ``[http] max_body_bytes`` value. Defaults to ``_LIMIT``.

    Returns:
        HttpClient: A client for ``https://example.com`` with that body limit.
    """
    config = ScanConfig.model_validate({"http": {"max_body_bytes": limit}})
    return HttpClient(Target.parse("https://example.com"), config)


class _Chunks(httpx.AsyncByteStream):
    """A response body served as the given raw chunks, so ``httpx`` decodes it as it streams."""

    def __init__(self, data: bytes, size: int = 4096) -> None:
        self._chunks = [data[i : i + size] for i in range(0, len(data), size)]

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk


def _gzip_response(payload: bytes) -> httpx.Response:
    """
    Args:
        payload (bytes): The plain body to compress.

    Returns:
        httpx.Response: A ``Content-Encoding: gzip`` response that streams the compressed bytes.
            (``pytest-httpx`` decodes a ``content=`` body at construction and then serves the
            plain bytes under a gzip header, so a stream is the faithful way to mock one.)
    """
    return httpx.Response(
        200, headers={"content-encoding": "gzip"}, stream=_Chunks(gzip.compress(payload))
    )


class _EndlessBody(httpx.AsyncByteStream):
    """A response body that never ends: 1 KiB chunks, counted as they are pulled."""

    def __init__(self) -> None:
        self.pulled = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        while self.pulled < 100_000:  # a guard, so a client with no limit ends the test too
            self.pulled += 1
            yield b"x" * 1024


async def test_a_body_over_the_limit_is_cut_and_counted(httpx_mock: object) -> None:
    """The first ``max_body_bytes`` are kept, the response is marked, and the stats count it."""
    httpx_mock.add_response(content=b"a" * 5000)  # type: ignore[attr-defined]
    async with _client() as http:
        response = await http.get(_URL)
    assert len(response.content) == _LIMIT and response.content == b"a" * _LIMIT
    assert response.truncated
    assert http.stats.truncated == 1


async def test_a_body_under_the_limit_is_untouched(httpx_mock: object) -> None:
    """The ordinary case does not change: the whole body, and nothing counted."""
    httpx_mock.add_response(text="hello world", headers={"content-type": "text/plain"})  # type: ignore[attr-defined]
    async with _client() as http:
        response = await http.get(_URL)
    assert response.text == "hello world"
    assert not response.truncated
    assert http.stats.truncated == 0


async def test_a_compressed_body_is_limited_after_decompression(httpx_mock: object) -> None:
    """A few KiB of gzip that inflate to megabytes is cut by what it expands to, not by its size."""
    bomb = bytes(5_000_000)  # five million zero bytes: tiny once compressed
    assert len(gzip.compress(bomb)) < _LIMIT * 20
    httpx_mock.add_callback(lambda request: _gzip_response(bomb))  # type: ignore[attr-defined]
    async with _client() as http:
        response = await http.get(_URL)
    assert len(response.content) == _LIMIT
    assert response.truncated


async def test_a_normal_compressed_body_still_decodes(httpx_mock: object) -> None:
    """Reading by stream must leave ``text`` working for ``Content-Encoding`` as before."""
    httpx_mock.add_callback(lambda request: _gzip_response(b"compressed but small"))  # type: ignore[attr-defined]
    async with _client() as http:
        response = await http.get(_URL)
    assert response.text == "compressed but small"
    assert not response.truncated


async def test_an_endless_body_stops_being_read_at_the_limit(httpx_mock: object) -> None:
    """The client stops pulling from a server that never stops sending."""
    stream = _EndlessBody()

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream)

    httpx_mock.add_callback(respond)  # type: ignore[attr-defined]
    async with _client(limit=10_000) as http:
        response = await http.get(_URL)
    assert len(response.content) == 10_000
    assert response.truncated
    assert stream.pulled <= 12  # ten chunks fill the limit; the one that crossed it, and no more


def test_the_truncation_warning_is_there_only_when_something_was_cut() -> None:
    """The scan says how many responses were cut and which setting bounds them."""
    assert truncated_warning(HttpStats(), 10 * 1024 * 1024) is None
    warning = truncated_warning(HttpStats(truncated=3), 10 * 1024 * 1024)
    assert warning is not None and "3 response(s)" in warning
    assert "10 MiB" in warning and "max_body_bytes" in warning


def test_the_limit_must_be_positive() -> None:
    """``max_body_bytes = 0`` would read nothing at all: it is a configuration error."""
    with pytest.raises(ValueError):
        ScanConfig.model_validate({"http": {"max_body_bytes": 0}})
