"""
Bounded content decoding of response bodies.

``httpx`` decodes ``Content-Encoding`` as it streams, but each network chunk is inflated in full
before the caller sees it, and a response that lists several codings is inflated through a chain
of decoders with no bound between them. The scanner reads responses from servers it does not
control, so it reads the raw bytes and decodes them itself: every stage, the raw bytes included,
stops at the body limit, and no single step produces more than ``_STEP`` bytes.

Only ``gzip`` and ``deflate`` are decoded, and the client asks for no other (``ACCEPT_ENCODING``).
A coding the scanner does not know is skipped, as ``httpx`` does when the library for it is not
installed, so a scan reads the same bytes whatever else is installed next to it.
"""

from __future__ import annotations

import zlib
from collections.abc import Iterator

import httpx

# What the client advertises: the codings :class:`BodyDecoder` decodes.
ACCEPT_ENCODING = "gzip, deflate"

# The most one decompression call may produce.
_STEP = 64 * 1024
# More codings than this in one response is not a real server: the body is not decoded.
_MAX_CODINGS = 3
_GZIP = frozenset({"gzip", "x-gzip"})
_DEFLATE = "deflate"


class _Inflater:
    """
    One ``gzip`` or ``deflate`` stage, fed piece by piece, each output step at most ``_STEP``.

    ``deflate`` is tried as zlib-wrapped data first and, if its first bytes are not, as raw
    deflate, the same tolerance ``httpx`` has. Data after the end of the compressed stream is
    ignored, as ``httpx`` ignores it.
    """

    def __init__(self, coding: str) -> None:
        """
        Args:
            coding (str): ``"gzip"``, ``"x-gzip"`` or ``"deflate"``.
        """
        self._deflate = coding == _DEFLATE
        wbits = zlib.MAX_WBITS if self._deflate else zlib.MAX_WBITS | 16
        self._inflater = zlib.decompressobj(wbits)
        self._started = False

    def feed(self, data: bytes) -> Iterator[bytes]:
        """
        Decode ``data`` lazily: the caller pulls one step at a time and may stop at any point.

        Args:
            data (bytes): The next input piece.

        Yields:
            bytes: Output pieces of at most ``_STEP`` bytes.

        Raises:
            httpx.DecodingError: When the data is not valid for the coding.
        """
        pending = data
        while pending and not self._inflater.eof:
            piece = self._step(pending)
            tail = self._inflater.unconsumed_tail
            if piece:
                yield piece
            elif tail == pending:
                return  # no progress: wait for more input
            pending = tail

    def _step(self, data: bytes) -> bytes:
        """
        Args:
            data (bytes): Input not yet consumed.

        Returns:
            bytes: At most ``_STEP`` bytes of output.

        Raises:
            httpx.DecodingError: When the data is not valid for the coding.
        """
        try:
            piece = self._inflater.decompress(data, _STEP)
        except zlib.error as exc:
            if not (self._deflate and not self._started):
                raise httpx.DecodingError(str(exc)) from exc
            self._deflate = False  # one fallback only: raw deflate
            self._inflater = zlib.decompressobj(-zlib.MAX_WBITS)
            try:
                piece = self._inflater.decompress(data, _STEP)
            except zlib.error as raw_exc:
                raise httpx.DecodingError(str(raw_exc)) from raw_exc
        self._started = True
        return piece

    def finish(self) -> bytes:
        """
        Returns:
            bytes: What the decompressor still holds once the input ended (under one window).

        Raises:
            httpx.DecodingError: When the data is not valid for the coding.
        """
        try:
            return self._inflater.flush()
        except zlib.error as exc:
            raise httpx.DecodingError(str(exc)) from exc


class BodyDecoder:
    """
    Decode a response body from its raw chunks, never holding more than ``limit`` bytes per stage.

    Attributes:
        cut (bool): Whether the body stopped at the limit (or was not decodable within it).
    """

    def __init__(self, content_encoding: list[str], limit: int) -> None:
        """
        Args:
            content_encoding (list[str]): The ``Content-Encoding`` values, in the order the
                server applied them (``httpx.Headers.get_list(..., split_commas=True)``).
            limit (int): The ``[http] max_body_bytes`` value.
        """
        codings = [value.strip().lower() for value in content_encoding]
        known = [coding for coding in codings if coding in _GZIP or coding == _DEFLATE]
        self._limit = limit
        self._body = bytearray()
        self._stages = [_Inflater(coding) for coding in reversed(known)]
        self._produced = [0] * len(self._stages)
        self._raw = 0
        self._too_many = len(known) > _MAX_CODINGS
        self.cut = self._too_many

    @property
    def body(self) -> bytes:
        """
        Returns:
            bytes: The decoded body so far, at most ``limit`` bytes.
        """
        return bytes(self._body)

    def feed(self, chunk: bytes) -> bool:
        """
        Decode the next raw chunk.

        Args:
            chunk (bytes): The next raw chunk from the network.

        Returns:
            bool: ``True`` when the body is complete as far as the limit goes: stop reading.

        Raises:
            httpx.DecodingError: When the data is not valid for its coding.
        """
        if self.cut:
            return True
        room = self._limit - self._raw
        if len(chunk) > room:
            chunk = chunk[:room]
            self.cut = True
        self._raw += len(chunk)
        self._emit(0, chunk)
        return self.cut

    def finish(self) -> None:
        """
        Flush every stage once the raw body ended, still within the limit.

        Raises:
            httpx.DecodingError: When the data is not valid for its coding.
        """
        for index, stage in enumerate(self._stages):
            if self.cut:
                return
            tail = self._charge(index, stage.finish())
            if tail:
                self._emit(index + 1, tail)

    def _emit(self, index: int, piece: bytes) -> None:
        """
        Run ``piece`` through the stages from ``index`` on and append what comes out.

        Args:
            index (int): The stage the piece enters (``len(stages)`` means the body itself).
            piece (bytes): Input for that stage.
        """
        if index == len(self._stages):
            room = self._limit - len(self._body)
            if len(piece) > room:
                piece = piece[:room]
                self.cut = True
            self._body += piece
            return
        for out in self._stages[index].feed(piece):
            kept = self._charge(index, out)
            if kept:
                self._emit(index + 1, kept)
            if self.cut:
                return  # stop pulling from the stage

    def _charge(self, index: int, piece: bytes) -> bytes:
        """
        Charge ``piece`` to stage ``index``'s budget, cutting it at the limit.

        Args:
            index (int): The stage that produced it.
            piece (bytes): Its output.

        Returns:
            bytes: The part of the output within the budget.
        """
        room = self._limit - self._produced[index]
        if len(piece) > room:
            piece = piece[:room]
            self.cut = True
        self._produced[index] += len(piece)
        return piece


__all__ = ["ACCEPT_ENCODING", "BodyDecoder"]
