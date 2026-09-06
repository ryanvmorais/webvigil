"""Shared test fixtures: a localhost TLS server backed by trustme certificates.

Value builders (``make_page`` / ``make_context`` / ``hardened_headers``) live in
``tests.support``.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import threading
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
import trustme


@dataclass
class RunningTlsServer:
    host: str
    port: int


class _TlsServer:
    def __init__(self, context: ssl.SSLContext) -> None:
        self._context = context
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self._sock.settimeout(0.25)
        self.port: int = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (TimeoutError, OSError):
                continue
            try:
                with (
                    self._context.wrap_socket(conn, server_side=True) as tls_conn,
                    contextlib.suppress(OSError),
                ):
                    tls_conn.recv(512)
            except (OSError, ssl.SSLError):
                pass

    def __enter__(self) -> RunningTlsServer:
        self._thread.start()
        return RunningTlsServer(host="127.0.0.1", port=self.port)

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        with contextlib.suppress(OSError):
            self._sock.close()


@pytest.fixture(scope="session")
def tls_ca() -> trustme.CA:
    return trustme.CA()


@pytest.fixture
def tls_server(tls_ca: trustme.CA):
    """Return a factory that starts a localhost TLS server with the given options."""

    @contextlib.contextmanager
    def _factory(
        *,
        max_version: ssl.TLSVersion | None = None,
        cert: trustme.LeafCert | None = None,
    ) -> Iterator[RunningTlsServer]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        leaf = cert or tls_ca.issue_cert("127.0.0.1")
        leaf.configure_cert(context)
        if max_version is not None:
            context.maximum_version = max_version
        with _TlsServer(context) as running:
            yield running

    return _factory
