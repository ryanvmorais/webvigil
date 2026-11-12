"""
The response-body limit of the HTTP client (``[http] max_body_bytes``) — security audit, 1.0.0.

A scanner reads responses from servers it does not control. Without a limit, ``httpx`` loads
the whole body into memory: a hostile server, a multi-gigabyte file reached by a probe or a
compressed body that inflates a thousandfold can exhaust the scanner. All requests go through
``pytest-httpx``; the endless-stream test counts how much the client actually pulled.
"""

from __future__ import annotations

import gzip
import zlib
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


# --- bounded decoding (security audit 2026-11): the limit holds at every stage ---------------


def _coded_response(raw: bytes, coding: str) -> httpx.Response:
    """
    Args:
        raw (bytes): The body as sent on the wire.
        coding (str): The ``Content-Encoding`` header value.

    Returns:
        httpx.Response: A streamed response with that header, served in 4 KiB chunks.
    """
    return httpx.Response(200, headers={"content-encoding": coding}, stream=_Chunks(raw))


async def test_a_body_coded_twice_is_bounded_while_it_is_decoded(httpx_mock: object) -> None:
    """Two gzip layers inflate stage by stage within the limit, not a whole stage at once."""
    import tracemalloc

    inner = gzip.compress(bytes(50_000_000))  # 50 MB of zeros, about 50 KB compressed
    httpx_mock.add_callback(  # type: ignore[attr-defined]
        lambda request: _coded_response(gzip.compress(inner), "gzip, gzip")
    )
    async with _client(limit=100_000) as http:
        tracemalloc.start()
        try:
            response = await http.get(_URL)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
    assert len(response.content) == 100_000
    assert response.truncated
    assert peak < 5_000_000  # a few decompression steps, never the 50 MB the body expands to


async def test_a_body_coded_twice_within_the_limit_decodes_whole(httpx_mock: object) -> None:
    """A legitimate double coding still yields the plain body."""
    payload = b"two layers, still readable"
    httpx_mock.add_callback(  # type: ignore[attr-defined]
        lambda request: _coded_response(gzip.compress(gzip.compress(payload)), "gzip, gzip")
    )
    async with _client() as http:
        response = await http.get(_URL)
    assert response.content == payload
    assert not response.truncated


@pytest.mark.parametrize("wbits", [zlib.MAX_WBITS, -zlib.MAX_WBITS])
async def test_deflate_decodes_wrapped_or_raw(httpx_mock: object, wbits: int) -> None:
    """``deflate`` accepts zlib-wrapped data and raw deflate, as ``httpx`` does."""
    packer = zlib.compressobj(wbits=wbits)
    raw = packer.compress(b"deflated body") + packer.flush()
    httpx_mock.add_callback(lambda request: _coded_response(raw, "deflate"))  # type: ignore[attr-defined]
    async with _client() as http:
        response = await http.get(_URL)
    assert response.content == b"deflated body"


async def test_an_unknown_coding_is_left_as_is(httpx_mock: object) -> None:
    """A coding the scanner does not decode is skipped, whatever library is installed."""
    httpx_mock.add_callback(lambda request: _coded_response(b"opaque", "br"))  # type: ignore[attr-defined]
    async with _client() as http:
        response = await http.get(_URL)
    assert response.content == b"opaque"


async def test_too_many_codings_are_not_decoded(httpx_mock: object) -> None:
    """A chain longer than any real server sends is not decoded at all, and the body is marked."""
    raw = b"x"
    for _ in range(4):
        raw = gzip.compress(raw)
    httpx_mock.add_callback(  # type: ignore[attr-defined]
        lambda request: _coded_response(raw, "gzip, gzip, gzip, gzip")
    )
    async with _client() as http:
        response = await http.get(_URL)
    assert response.content == b""
    assert response.truncated


async def test_data_after_the_compressed_stream_is_ignored(httpx_mock: object) -> None:
    """Bytes after the end of the gzip stream are dropped, not kept or decoded."""
    raw = gzip.compress(b"body") + bytes(200_000)
    httpx_mock.add_callback(lambda request: _coded_response(raw, "gzip"))  # type: ignore[attr-defined]
    async with _client(limit=10_000_000) as http:
        response = await http.get(_URL)
    assert response.content == b"body"


async def test_the_client_asks_only_for_what_it_decodes(httpx_mock: object) -> None:
    """``Accept-Encoding`` names the codings the bounded decoder handles, no others."""
    httpx_mock.add_response(content=b"ok")  # type: ignore[attr-defined]
    async with _client() as http:
        await http.get(_URL)
    sent = httpx_mock.get_requests()[0]  # type: ignore[attr-defined]
    assert sent.headers["accept-encoding"] == "gzip, deflate"
