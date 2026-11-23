"""
The engine's TLS contexts and the trust of an HTTPS proxy (spec 023: RF-02, RF-03, RF-07, ADR-2).

Real handshakes stay on loopback, against a small ``asyncio`` server with a ``trustme``
certificate. The autouse fixture clears the trust and proxy variables, so the environment of
whoever runs the suite cannot change a verdict, and zeroes the retry backoff.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import certifi
import h2.config
import h2.connection
import h2.events
import httpcore2
import httpx2
import pytest
import trustme

from webvigil.checks.deps import osv as osv_mod
from webvigil.checks.deps.osv import OsvProvider
from webvigil.core.config import ScanConfig
from webvigil.core.errors import RequestFailed
from webvigil.core.target import Target
from webvigil.http import client as client_mod
from webvigil.http.client import HttpClient
from webvigil.http.tls import client_ssl_context, pin_proxy_trust

_BODY = b"served over tls"
_VERIFY_FAILED = "CERTIFICATE_VERIFY_FAILED"
_PROXY_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """No trust or proxy variable from the outside, and no real wait between retries."""
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", *_PROXY_VARIABLES):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    monkeypatch.setattr(client_mod, "BACKOFF_BASE_S", 0.0)
    monkeypatch.setattr(client_mod, "BACKOFF_JITTER_S", 0.0)


def _write_ca(ca: trustme.CA, directory: Path, name: str = "ca.pem") -> str:
    """
    Args:
        ca (trustme.CA): The certificate authority.
        directory (Path): Where to write it.
        name (str): The file name. Defaults to ``"ca.pem"``.

    Returns:
        str: The path of the PEM file.
    """
    path = directory / name
    ca.cert_pem.write_to_path(str(path))
    return str(path)


def _der(ca: trustme.CA) -> bytes:
    """
    Args:
        ca (trustme.CA): The certificate authority.

    Returns:
        bytes: Its certificate in DER, the form ``get_ca_certs(binary_form=True)`` returns.
    """
    return ssl.PEM_cert_to_DER_cert(ca.cert_pem.bytes().decode("ascii"))


# ---------------------------------------------------------------------------
# A loopback HTTPS server
# ---------------------------------------------------------------------------


@dataclass
class _Served:
    """
    What the test server saw.

    Attributes:
        port (int): The port it listens on.
        protocols (list[str | None]): The ALPN protocol of each accepted connection.
    """

    port: int = 0
    protocols: list[str | None] = field(default_factory=list)


async def _answer_http1(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """
    Args:
        reader (asyncio.StreamReader): The connection's reader.
        writer (asyncio.StreamWriter): The connection's writer.
    """
    await reader.readuntil(b"\r\n\r\n")
    head = (
        "HTTP/1.1 200 OK\r\nset-cookie: a=1\r\nset-cookie: b=2\r\n"
        f"content-length: {len(_BODY)}\r\nconnection: close\r\n\r\n"
    )
    writer.write(head.encode("ascii") + _BODY)
    await writer.drain()


async def _answer_h2(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """
    Args:
        reader (asyncio.StreamReader): The connection's reader.
        writer (asyncio.StreamWriter): The connection's writer.
    """
    connection = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False))
    connection.initiate_connection()
    writer.write(connection.data_to_send())
    await writer.drain()
    while data := await reader.read(65536):
        for event in connection.receive_data(data):
            if isinstance(event, h2.events.RequestReceived):
                headers = [
                    (":status", "200"),
                    ("set-cookie", "a=1"),
                    ("set-cookie", "b=2"),
                    ("content-length", str(len(_BODY))),
                ]
                connection.send_headers(event.stream_id, headers)
                connection.send_data(event.stream_id, _BODY, end_stream=True)
        writer.write(connection.data_to_send())
        await writer.drain()


@contextlib.asynccontextmanager
async def _serve(
    cert: trustme.LeafCert, *, alpn: tuple[str, ...] = ("http/1.1",)
) -> AsyncIterator[_Served]:
    """
    Args:
        cert (trustme.LeafCert): The server's certificate.
        alpn (tuple[str, ...]): The protocols it offers. Defaults to HTTP/1.1 only.

    Yields:
        _Served: The port and the record of what the server saw.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert.configure_cert(context)
    context.set_alpn_protocols(list(alpn))
    served = _Served()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        protocol = writer.get_extra_info("ssl_object").selected_alpn_protocol()
        served.protocols.append(protocol)
        answer = _answer_h2 if protocol == "h2" else _answer_http1
        with contextlib.suppress(ConnectionError, ssl.SSLError, asyncio.IncompleteReadError):
            await answer(reader, writer)
        writer.close()
        with contextlib.suppress(ConnectionError, ssl.SSLError):
            await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    served.port = server.sockets[0].getsockname()[1]
    async with server:
        yield served


def _http(port: int, *, verify_tls: bool = True) -> HttpClient:
    """
    Args:
        port (int): The loopback port of the target.
        verify_tls (bool): The scan's ``verify_tls``. Defaults to ``True``.

    Returns:
        HttpClient: A scan client for that target.
    """
    config = ScanConfig.model_validate({"http": {"verify_tls": verify_tls}})
    return HttpClient(Target.parse(f"https://127.0.0.1:{port}"), config)


@contextlib.asynccontextmanager
async def _engine_client(kind: str) -> AsyncIterator[httpx2.AsyncClient]:
    """
    Args:
        kind (str): ``"scan"`` for the scan's client, ``"osv"`` for the OSV.dev client.

    Yields:
        httpx2.AsyncClient: The open client. Nothing is sent through it.
    """
    if kind == "scan":
        async with HttpClient(Target.parse("https://example.com"), ScanConfig()) as http:
            yield http._active_client
    else:
        async with OsvProvider("https://osv.test", 1.0, user_agent="test")._client() as client:
            yield client


# ---------------------------------------------------------------------------
# client_ssl_context: the sources and their precedence (RF-02, RF-03)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("file_value", "dir_value", "expected"),
    [
        ("/ca/file.pem", None, {"cafile": "/ca/file.pem"}),
        (None, "/ca/dir", {"capath": "/ca/dir"}),
        ("/ca/file.pem", "/ca/dir", {"cafile": "/ca/file.pem"}),
        ("", "/ca/dir", {"capath": "/ca/dir"}),
        (None, None, {"cafile": "/certifi.pem"}),
        ("", "", {"cafile": "/certifi.pem"}),
    ],
)
def test_the_trust_source_follows_the_environment(
    monkeypatch: pytest.MonkeyPatch,
    file_value: str | None,
    dir_value: str | None,
    expected: dict[str, str],
) -> None:
    """``SSL_CERT_FILE`` wins over ``SSL_CERT_DIR``, an empty one is unset, ``certifi`` is last."""
    if file_value is not None:
        monkeypatch.setenv("SSL_CERT_FILE", file_value)
    if dir_value is not None:
        monkeypatch.setenv("SSL_CERT_DIR", dir_value)
    monkeypatch.setattr(certifi, "where", lambda: "/certifi.pem")
    calls: list[dict[str, Any]] = []
    built = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    def spy(**kwargs: Any) -> ssl.SSLContext:
        calls.append(kwargs)
        return built

    monkeypatch.setattr(ssl, "create_default_context", spy)
    assert client_ssl_context() is built
    assert calls == [expected]


def test_by_default_the_context_holds_exactly_the_certifi_bundle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tls_ca: trustme.CA
) -> None:
    """Nothing from the operating system's store is added to the bundle."""
    monkeypatch.setattr(certifi, "where", lambda: _write_ca(tls_ca, tmp_path))
    context = client_ssl_context()
    assert context.get_ca_certs(binary_form=True) == [_der(tls_ca)]
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_ssl_cert_file_replaces_the_bundle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tls_ca: trustme.CA
) -> None:
    """The context holds the file's CA and not the one in the ``certifi`` bundle."""
    in_bundle = trustme.CA()
    monkeypatch.setattr(certifi, "where", lambda: _write_ca(in_bundle, tmp_path, "bundle.pem"))
    monkeypatch.setenv("SSL_CERT_FILE", _write_ca(tls_ca, tmp_path))
    assert client_ssl_context().get_ca_certs(binary_form=True) == [_der(tls_ca)]


def test_an_unreadable_ca_file_raises_when_the_client_is_built(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A wrong ``SSL_CERT_FILE`` is an error, never a silent fallback to another source."""
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "missing.pem"))
    with pytest.raises(OSError):
        client_ssl_context()


def test_verification_off_checks_nothing_and_ignores_the_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With ``verify=False`` even an unreadable ``SSL_CERT_FILE`` is not opened."""
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "missing.pem"))
    context = client_ssl_context(verify=False)
    assert context.verify_mode is ssl.CERT_NONE
    assert context.check_hostname is False
    assert context.get_ca_certs() == []


def test_each_call_builds_a_new_context() -> None:
    """Clients never share a context: the transport writes ALPN onto the one it gets (ADR-1)."""
    assert client_ssl_context() is not client_ssl_context()


# ---------------------------------------------------------------------------
# Both clients use the context they built (RF-02, RF-03)
# ---------------------------------------------------------------------------


@pytest.fixture
def built(monkeypatch: pytest.MonkeyPatch) -> list[tuple[bool, ssl.SSLContext]]:
    """
    Args:
        monkeypatch (pytest.MonkeyPatch): Wraps ``client_ssl_context`` in both client modules.

    Returns:
        list[tuple[bool, ssl.SSLContext]]: The ``verify`` and the result of each call.
    """
    calls: list[tuple[bool, ssl.SSLContext]] = []

    def spy(*, verify: bool = True) -> ssl.SSLContext:
        context = client_ssl_context(verify=verify)
        calls.append((verify, context))
        return context

    monkeypatch.setattr(client_mod, "client_ssl_context", spy)
    monkeypatch.setattr(osv_mod, "client_ssl_context", spy)
    return calls


@pytest.mark.parametrize("verify_tls", [True, False])
async def test_the_scan_client_uses_the_context_it_built(
    built: list[tuple[bool, ssl.SSLContext]], verify_tls: bool
) -> None:
    """The transport's context is the engine's, built with the scan's ``verify_tls``."""
    async with _http(443, verify_tls=verify_tls) as http:
        pool = http._active_client._transport._pool
        assert [flag for flag, _ in built] == [verify_tls]
        assert pool._ssl_context is built[0][1]


async def test_the_osv_client_uses_its_context_and_always_verifies(
    built: list[tuple[bool, ssl.SSLContext]],
) -> None:
    """OSV.dev is verified whatever the scan says: its client takes no ``verify_tls``."""
    async with _engine_client("osv") as client:
        context = client._transport._pool._ssl_context
    assert [flag for flag, _ in built] == [True]
    assert context is built[0][1]
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True


# ---------------------------------------------------------------------------
# Real handshakes (RF-02, RF-03)
# ---------------------------------------------------------------------------


async def test_a_ca_in_the_trust_source_is_accepted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tls_ca: trustme.CA
) -> None:
    """The control of the two refusals below: same server, its CA trusted."""
    monkeypatch.setenv("SSL_CERT_FILE", _write_ca(tls_ca, tmp_path))
    async with (
        _serve(tls_ca.issue_cert("127.0.0.1")) as served,
        _http(served.port) as http,
    ):
        response = await http.get(f"https://127.0.0.1:{served.port}/")
    assert (response.status_code, response.content) == (200, _BODY)


@pytest.mark.parametrize("source", ["another-file", "certifi"])
async def test_a_ca_outside_the_trust_source_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tls_ca: trustme.CA, source: str
) -> None:
    """A throwaway CA is in neither another file nor the real ``certifi`` bundle."""
    if source == "another-file":
        monkeypatch.setenv("SSL_CERT_FILE", _write_ca(trustme.CA(), tmp_path))
    async with (
        _serve(tls_ca.issue_cert("127.0.0.1")) as served,
        _http(served.port) as http,
    ):
        with pytest.raises(RequestFailed, match=_VERIFY_FAILED):
            await http.get(f"https://127.0.0.1:{served.port}/")
    assert served.protocols == []


async def test_verification_off_accepts_an_untrusted_ca_and_another_name(
    tls_ca: trustme.CA,
) -> None:
    """``verify_tls=False`` connects where the same call with verification on is refused."""
    async with _serve(tls_ca.issue_cert("other.test")) as served:
        url = f"https://127.0.0.1:{served.port}/"
        async with _http(served.port) as http:
            with pytest.raises(RequestFailed, match=_VERIFY_FAILED):
                await http.get(url)
        async with _http(served.port, verify_tls=False) as http:
            response = await http.get(url)
    assert (response.status_code, response.content) == (200, _BODY)


# ---------------------------------------------------------------------------
# HTTP/2 through the guarded transport (RF-07)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("offered", "negotiated"),
    [(("h2", "http/1.1"), "h2"), (("http/1.1",), "http/1.1")],
)
async def test_the_client_speaks_what_the_server_negotiates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    tls_ca: trustme.CA,
    offered: tuple[str, ...],
    negotiated: str,
) -> None:
    """HTTP/2 keeps the status, body and repeated headers; HTTP/1.1 is the control."""
    monkeypatch.setenv("SSL_CERT_FILE", _write_ca(tls_ca, tmp_path))
    async with (
        _serve(tls_ca.issue_cert("127.0.0.1"), alpn=offered) as served,
        _http(served.port) as http,
    ):
        response = await http.get(f"https://127.0.0.1:{served.port}/")
        assert "127.0.0.1" in http.addresses._pinned  # the connection went through the guard
    assert served.protocols == [negotiated]
    assert (response.status_code, response.content) == (200, _BODY)
    assert response.headers.get_list("set-cookie") == ["a=1", "b=2"]


# ---------------------------------------------------------------------------
# The connection to a proxy (ADR-2)
# ---------------------------------------------------------------------------


def _proxy_pool(client: httpx2.AsyncClient) -> httpcore2.AsyncHTTPProxy:
    """
    Args:
        client (httpx2.AsyncClient): A client with one proxy mount.

    Returns:
        httpcore2.AsyncHTTPProxy: The pool of that mount.
    """
    (transport,) = [t for t in client._mounts.values() if t is not None]
    pool = transport._pool
    assert isinstance(pool, httpcore2.AsyncHTTPProxy)
    return pool


@pytest.mark.parametrize("kind", ["scan", "osv"])
async def test_an_https_proxy_gets_the_system_store_plus_certifi(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tls_ca: trustme.CA, kind: str
) -> None:
    """The proxy leg has its own trust, and the leg to the target keeps the client's context."""
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy.test:8443")
    monkeypatch.setattr(certifi, "where", lambda: _write_ca(tls_ca, tmp_path))
    calls: list[dict[str, Any]] = []
    real: Callable[..., ssl.SSLContext] = ssl.create_default_context

    def spy(**kwargs: Any) -> ssl.SSLContext:
        calls.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(ssl, "create_default_context", spy)
    async with _engine_client(kind) as client:
        pool = _proxy_pool(client)
        pinned = pool._proxy_ssl_context
        connection = pool.create_connection(httpcore2.Origin(b"https", b"example.test", 443))
    assert pinned is not None
    assert {} in calls  # the no-argument call is the one that loads the system store
    assert _der(tls_ca) in pinned.get_ca_certs(binary_form=True)
    assert pinned.verify_mode is ssl.CERT_REQUIRED
    target_context = client._transport._pool._ssl_context
    assert pinned is not target_context
    assert connection._connection._ssl_context is pinned
    assert connection._ssl_context is target_context


@pytest.mark.parametrize("kind", ["scan", "osv"])
async def test_an_http_proxy_has_no_tls_context(monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    """``httpcore2`` refuses a proxy context on an ``http://`` proxy, so none is set."""
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.test:3128")
    async with _engine_client(kind) as client:
        assert _proxy_pool(client)._proxy_ssl_context is None


async def test_a_no_proxy_entry_is_skipped_and_the_proxy_still_pinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``NO_PROXY`` host is a mount with no transport, next to the real proxy."""
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy.test:8443")
    monkeypatch.setenv("NO_PROXY", "internal.test")
    async with _engine_client("scan") as client:
        assert None in client._mounts.values()
        assert _proxy_pool(client)._proxy_ssl_context is not None


def test_a_socks_proxy_is_left_alone() -> None:
    """A SOCKS proxy has no TLS leg of its own, and it is not an unknown layout."""
    pool = object.__new__(httpcore2.AsyncSOCKSProxy)  # its constructor needs ``socksio``
    client = SimpleNamespace(_mounts={"all://": SimpleNamespace(_pool=pool)})
    pin_proxy_trust(client)  # type: ignore[arg-type]  # a stand-in with only ``_mounts``
    assert not hasattr(pool, "_proxy_ssl_context")


@pytest.mark.parametrize(
    "pool",
    [
        None,
        SimpleNamespace(_proxy_ssl_context=None),
        object.__new__(httpcore2.AsyncHTTPProxy),
    ],
    ids=["no-pool", "another-class-with-the-attribute", "no-proxy-context-attribute"],
)
def test_an_unknown_mount_layout_raises(pool: object) -> None:
    """A layout this code does not know never connects with some other context."""
    client = SimpleNamespace(_mounts={"all://": SimpleNamespace(_pool=pool)})
    with pytest.raises(RuntimeError, match="unexpected httpx2 proxy layout"):
        pin_proxy_trust(client)  # type: ignore[arg-type]  # a stand-in with only ``_mounts``
