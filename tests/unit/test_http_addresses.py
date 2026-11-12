"""
The address guard: names resolve once per scan, and a public target keeps the scan off internal
addresses.

The resolver is a seam (a dict-backed fake), and the network backend under the guard is a fake
that records where it was asked to connect, so no test opens a socket or asks a real DNS server.
"""

from __future__ import annotations

from collections.abc import Iterable

import httpcore
import httpx
import pytest

from webvigil.core.config import ScanConfig
from webvigil.core.errors import RequestFailed
from webvigil.core.target import Scope, Target
from webvigil.http import client as client_mod
from webvigil.http.addresses import (
    AddressGuard,
    BlockedAddressError,
    GuardedBackend,
    install,
    is_public,
)
from webvigil.http.client import HttpClient, HttpStats, blocked_address_warning
from webvigil.http.tls_probe import probe


class _Resolver:
    """A fake resolver: answers from a mutable table and counts the questions per host."""

    def __init__(self, table: dict[str, list[str]]) -> None:
        """
        Args:
            table (dict[str, list[str]]): Host name to the addresses it resolves to.
        """
        self.table = table
        self.asked: dict[str, int] = {}

    async def __call__(self, host: str, port: int) -> list[str]:
        """
        Args:
            host (str): The host name.
            port (int): The port (ignored).

        Returns:
            list[str]: The addresses in the table.

        Raises:
            httpcore.ConnectError: For a host the table does not know.
        """
        self.asked[host] = self.asked.get(host, 0) + 1
        if host not in self.table:
            raise httpcore.ConnectError(f"{host}: unknown")
        return list(self.table[host])


class _Inner(httpcore.AsyncNetworkBackend):
    """A fake network backend: records each connect and refuses the addresses it is told to."""

    def __init__(self, refuse: Iterable[str] = ()) -> None:
        """
        Args:
            refuse (Iterable[str]): Addresses whose connection fails.
        """
        self.refuse = set(refuse)
        self.connected: list[str] = []

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        """
        Args:
            host (str): The address the guard chose.
            port (int): The port.
            timeout (float | None): Ignored.
            local_address (str | None): Ignored.
            socket_options (Iterable[httpcore.SOCKET_OPTION] | None): Ignored.

        Returns:
            httpcore.AsyncNetworkStream: A mock stream.

        Raises:
            httpcore.ConnectError: For a refused address.
        """
        self.connected.append(host)
        if host in self.refuse:
            raise httpcore.ConnectError(f"{host}: refused")
        return httpcore.AsyncMockStream([])


_PUBLIC = "93.184.216.34"
_PUBLIC_2 = "93.184.216.35"


# ---------------------------------------------------------------------------
# What counts as public
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",  # cloud metadata
        "100.64.0.1",  # shared address space
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::1",
        "fe80::1%2",
        "fc00::1",
        "fd12:3456::1",
        "ff02::1",
        "::ffff:127.0.0.1",  # IPv4-mapped
        "::ffff:10.0.0.1",
        "2002:7f00:1::1",  # 6to4 around 127.0.0.1
        "2002:a00:5::1",  # 6to4 around 10.0.0.5
        "64:ff9b::a00:5",  # NAT64 around 10.0.0.5
        "not-an-address",
    ],
)
def test_internal_addresses_are_not_public(address: str) -> None:
    """Loopback, private, link-local, metadata and the IPv6 forms that carry them are internal."""
    assert not is_public(address)


@pytest.mark.parametrize(
    "address", [_PUBLIC, "8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808"]
)
def test_public_addresses_are_public(address: str) -> None:
    """A globally reachable unicast address, in any form, is public."""
    assert is_public(address)


# ---------------------------------------------------------------------------
# The guard
# ---------------------------------------------------------------------------


async def test_a_public_target_keeps_every_host_off_internal_addresses() -> None:
    """An in-scope name that resolves to an internal address is refused for a public target."""
    resolver = _Resolver(
        {"www.example.com": [_PUBLIC], "intra.example.com": ["10.0.0.5"], "lo.example.com": ["::1"]}
    )
    guard = AddressGuard("www.example.com", resolver=resolver)
    assert await guard.addresses("www.example.com", 443) == [_PUBLIC]
    for host in ("intra.example.com", "lo.example.com"):
        with pytest.raises(BlockedAddressError):
            await guard.addresses(host, 443)


async def test_a_mixed_answer_keeps_only_its_public_addresses() -> None:
    """A name that resolves to public and internal addresses is reached on the public ones only."""
    resolver = _Resolver({"www.example.com": ["127.0.0.1", _PUBLIC, "10.0.0.1", _PUBLIC_2]})
    guard = AddressGuard("www.example.com", resolver=resolver)
    assert await guard.addresses("www.example.com", 443) == [_PUBLIC, _PUBLIC_2]


async def test_an_internal_target_may_reach_internal_addresses() -> None:
    """A target the user pointed at an internal address is scanned there."""
    resolver = _Resolver({"localhost": ["::1", "127.0.0.1"], "app": ["172.18.0.3"]})
    assert await AddressGuard("localhost", resolver=resolver).addresses("localhost", 8000) == [
        "::1",
        "127.0.0.1",
    ]
    assert await AddressGuard("app", resolver=resolver).addresses("app", 8000) == ["172.18.0.3"]


async def test_a_name_resolves_once_per_scan() -> None:
    """A later answer for the same name is never asked for, so a name cannot move mid-scan."""
    resolver = _Resolver({"www.example.com": [_PUBLIC], "api.example.com": [_PUBLIC_2]})
    guard = AddressGuard("www.example.com", resolver=resolver)
    assert await guard.addresses("api.example.com", 443) == [_PUBLIC_2]
    resolver.table["api.example.com"] = ["127.0.0.1"]
    resolver.table["www.example.com"] = ["127.0.0.1"]
    assert await guard.addresses("api.example.com", 443) == [_PUBLIC_2]
    assert await guard.addresses("WWW.example.com", 80) == [_PUBLIC]
    assert resolver.asked == {"www.example.com": 1, "api.example.com": 1}


async def test_a_refused_name_stays_refused() -> None:
    """The refusal is pinned too: a later public answer does not let the name in."""
    resolver = _Resolver({"www.example.com": [_PUBLIC], "intra.example.com": ["10.0.0.5"]})
    guard = AddressGuard("www.example.com", resolver=resolver)
    with pytest.raises(BlockedAddressError):
        await guard.addresses("intra.example.com", 443)
    resolver.table["intra.example.com"] = [_PUBLIC_2]
    with pytest.raises(BlockedAddressError):
        await guard.addresses("intra.example.com", 443)


async def test_a_failed_resolution_is_not_pinned() -> None:
    """A name that did not resolve is asked again next time, like a transient DNS error."""
    resolver = _Resolver({"www.example.com": [_PUBLIC]})
    guard = AddressGuard("www.example.com", resolver=resolver)
    with pytest.raises(httpcore.ConnectError):
        await guard.addresses("late.example.com", 443)
    resolver.table["late.example.com"] = [_PUBLIC_2]
    assert await guard.addresses("late.example.com", 443) == [_PUBLIC_2]


# ---------------------------------------------------------------------------
# The backend connects to the checked address
# ---------------------------------------------------------------------------


async def test_the_backend_connects_to_the_checked_address_not_the_name() -> None:
    """The socket goes to the pinned address; the name is never resolved again."""
    resolver = _Resolver({"www.example.com": ["10.9.9.9", _PUBLIC]})
    inner = _Inner()
    backend = GuardedBackend(AddressGuard("www.example.com", resolver=resolver), inner)
    await backend.connect_tcp("www.example.com", 443, timeout=5)
    assert inner.connected == [_PUBLIC]


async def test_the_backend_falls_back_to_the_next_allowed_address() -> None:
    """When the first allowed address does not answer, the next one is tried."""
    resolver = _Resolver({"www.example.com": [_PUBLIC, _PUBLIC_2]})
    inner = _Inner(refuse=[_PUBLIC])
    backend = GuardedBackend(AddressGuard("www.example.com", resolver=resolver), inner)
    await backend.connect_tcp("www.example.com", 443, timeout=5)
    assert inner.connected == [_PUBLIC, _PUBLIC_2]
    with pytest.raises(httpcore.ConnectError):
        await GuardedBackend(
            AddressGuard("www.example.com", resolver=resolver), _Inner(refuse=[_PUBLIC, _PUBLIC_2])
        ).connect_tcp("www.example.com", 443)


async def test_a_refused_host_never_reaches_the_socket() -> None:
    """A host the guard refuses is not connected to at all."""
    resolver = _Resolver({"www.example.com": [_PUBLIC], "intra.example.com": ["10.0.0.5"]})
    inner = _Inner()
    backend = GuardedBackend(AddressGuard("www.example.com", resolver=resolver), inner)
    with pytest.raises(BlockedAddressError):
        await backend.connect_tcp("intra.example.com", 443)
    assert inner.connected == []


async def test_a_slow_resolution_is_a_connect_timeout() -> None:
    """The connect timeout covers the name resolution too."""

    async def hang(host: str, port: int) -> list[str]:
        import asyncio

        await asyncio.sleep(10)
        return [_PUBLIC]

    backend = GuardedBackend(AddressGuard("www.example.com", resolver=hang), _Inner())
    with pytest.raises(httpcore.ConnectTimeout):
        await backend.connect_tcp("www.example.com", 443, timeout=0.05)


def test_install_refuses_a_layout_it_does_not_know() -> None:
    """Without the expected httpx internals the scan fails loudly instead of running unguarded."""
    with pytest.raises(RuntimeError):
        install(object(), AddressGuard("www.example.com"))


# ---------------------------------------------------------------------------
# Through HttpClient
# ---------------------------------------------------------------------------


def _client(resolver: _Resolver) -> HttpClient:
    """
    Args:
        resolver (_Resolver): The fake resolver.

    Returns:
        HttpClient: A client for ``https://www.example.com`` under ``Scope.SUBDOMAINS``.
    """
    return HttpClient(
        Target.parse("https://www.example.com", scope=Scope.SUBDOMAINS),
        ScanConfig(),
        resolver=resolver,
    )


async def test_the_client_routes_its_connections_through_the_guard() -> None:
    """The client's default transport connects through the guarded backend."""
    http = _client(_Resolver({}))
    async with http:
        transport = http._active_client._transport
        backend = transport._pool._network_backend  # type: ignore[attr-defined]
        assert isinstance(backend, GuardedBackend)


async def test_the_client_keeps_the_proxy_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Installing the guard does not turn off ``HTTPS_PROXY`` (the proxy resolves names there)."""
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.internal:3128")
    async with _client(_Resolver({})) as http:
        assert any(m is not None for m in http._active_client._mounts.values())


async def test_a_request_to_an_internal_subdomain_is_refused_without_a_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal is counted once, not retried, and not mistaken for an unreachable target."""
    monkeypatch.setattr(client_mod, "BACKOFF_BASE_S", 0.0)
    monkeypatch.setattr(client_mod, "BACKOFF_JITTER_S", 0.0)
    resolver = _Resolver({"www.example.com": [_PUBLIC], "intra.example.com": ["10.0.0.5"]})
    http = _client(resolver)
    async with http:
        with pytest.raises(RequestFailed):
            await http.get("https://intra.example.com/admin")
    assert http.stats.blocked_address == 1
    assert http.stats.retries == 0
    assert http.stats.failed == 0
    assert resolver.asked == {"www.example.com": 1, "intra.example.com": 1}
    assert blocked_address_warning(http.stats) is not None


def test_no_warning_when_nothing_was_refused() -> None:
    """A scan whose hosts all resolved to allowed addresses carries no address warning."""
    assert blocked_address_warning(HttpStats()) is None


async def test_the_tls_probe_does_not_connect_to_a_refused_host() -> None:
    """The TLS check's own socket follows the same rule as every request."""
    resolver = _Resolver({"www.example.com": [_PUBLIC], "intra.example.com": ["10.0.0.5"]})
    guard = AddressGuard("www.example.com", resolver=resolver)
    result = await probe("intra.example.com", 443, guard=guard)
    assert not result.reachable
    assert "BlockedAddressError" in (result.error or "")


async def test_the_httpx_error_keeps_the_guard_refusal_as_its_cause() -> None:
    """The client tells a refusal apart through the cause ``httpx`` keeps on its own error."""
    resolver = _Resolver({"www.example.com": [_PUBLIC], "intra.example.com": ["10.0.0.5"]})
    transport = httpx.AsyncHTTPTransport()
    install(transport, AddressGuard("www.example.com", resolver=resolver))
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(httpx.ConnectError) as caught:
            await client.get("https://intra.example.com/")
    assert isinstance(caught.value.__cause__, BlockedAddressError)
