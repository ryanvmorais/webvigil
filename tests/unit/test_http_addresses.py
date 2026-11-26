"""
The address guard: names resolve once per scan, and a public target keeps the scan off internal
addresses.

The resolver is a seam (a dict-backed fake), and the network backend under the guard is a fake
that records where it was asked to connect, so no test opens a socket or asks a real DNS server.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

import httpcore2
import httpx2
import pytest

from webvigil.core.config import ScanConfig
from webvigil.core.errors import RequestFailed
from webvigil.core.target import Scope, Target
from webvigil.http import client as client_mod
from webvigil.http.addresses import (
    MAX_LEFT_OUT_LINES,
    AddressGuard,
    AddressNotices,
    BlockedAddressError,
    GuardedBackend,
    _embedded_ipv4,
    address_warnings,
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
            httpcore2.ConnectError: For a host the table does not know.
        """
        self.asked[host] = self.asked.get(host, 0) + 1
        if host not in self.table:
            raise httpcore2.ConnectError(f"{host}: unknown")
        return list(self.table[host])


class _Inner(httpcore2.AsyncNetworkBackend):
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
        socket_options: Iterable[httpcore2.SOCKET_OPTION] | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        """
        Args:
            host (str): The address the guard chose.
            port (int): The port.
            timeout (float | None): Ignored.
            local_address (str | None): Ignored.
            socket_options (Iterable[httpcore2.SOCKET_OPTION] | None): Ignored.

        Returns:
            httpcore2.AsyncNetworkStream: A mock stream.

        Raises:
            httpcore2.ConnectError: For a refused address.
        """
        self.connected.append(host)
        if host in self.refuse:
            raise httpcore2.ConnectError(f"{host}: refused")
        return httpcore2.AsyncMockStream([])


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
        "::a00:5",  # IPv4-compatible around 10.0.0.5
        "::7f00:1",  # IPv4-compatible around 127.0.0.1
        "::ffff:ffff",  # last IPv4-compatible address
        "::ffff:0:0:0",  # first IPv4-translated address
        "::ffff:0:a00:5",  # IPv4-translated around 10.0.0.5
        "::ffff:0:ffff:ffff",  # last IPv4-translated address
        "fec0::",  # first site-local address
        "fec0::1",
        "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",  # last site-local address
        "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",  # just below: link-local
        "ff00::",  # just above: multicast
        "1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",  # just below global unicast
        "4000::",  # just above global unicast
        "2001:db8::1",  # documentation, inside global unicast
        "::1:0:0",  # reserved, next to the IPv4-compatible range
        "::ffff:1:0:0",  # reserved, next to the IPv4-translated range
        "400::1",  # reserved
        "not-an-address",
    ],
)
def test_internal_addresses_are_not_public(address: str) -> None:
    """Loopback, private, link-local, metadata and the IPv6 forms that carry them are internal."""
    assert not is_public(address)


@pytest.mark.parametrize(
    "address",
    [
        _PUBLIC,
        "8.8.8.8",
        "2606:4700:4700::1111",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "::808:808",  # IPv4-compatible around a public address
        "::ffff:0:808:808",  # IPv4-translated around a public address
        "2000::",  # first global unicast address
        "3000::1",
        "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",  # last global unicast address
    ],
)
def test_public_addresses_are_public(address: str) -> None:
    """A globally reachable unicast address, in any form, is public."""
    assert is_public(address)


@pytest.mark.parametrize(
    ("address", "inner"),
    [
        ("::", "0.0.0.0"),
        ("::a00:5", "10.0.0.5"),
        ("::ffff:ffff", "255.255.255.255"),
        ("::ffff:0:0:0", "0.0.0.0"),
        ("::ffff:0:a00:5", "10.0.0.5"),
        ("::ffff:0:ffff:ffff", "255.255.255.255"),
    ],
)
def test_the_ipv4_inside_each_end_of_the_embedding_ranges_is_read(address: str, inner: str) -> None:
    """Both ends of the IPv4-compatible and IPv4-translated ranges yield their IPv4 address."""
    assert str(_embedded_ipv4(ipaddress.IPv6Address(address))) == inner


@pytest.mark.parametrize(
    "address",
    [
        "::1:0:0",  # just past the IPv4-compatible range
        "::fffe:ffff:ffff:ffff",  # just before the IPv4-translated range
        "::ffff:1:0:0",  # just past it
    ],
)
def test_a_neighbour_of_the_embedding_ranges_carries_no_ipv4(address: str) -> None:
    """The address next to a range is not read as if it held an IPv4 address."""
    assert _embedded_ipv4(ipaddress.IPv6Address(address)) is None


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
    with pytest.raises(httpcore2.ConnectError):
        await guard.addresses("late.example.com", 443)
    resolver.table["late.example.com"] = [_PUBLIC_2]
    assert await guard.addresses("late.example.com", 443) == [_PUBLIC_2]


# ---------------------------------------------------------------------------
# The notices: what the guard saw that the user should know (spec 026, RF-06, RF-07)
# ---------------------------------------------------------------------------


async def test_a_public_name_resolving_only_inside_is_reported_and_still_scanned() -> None:
    """The scan reaches the internal addresses, and the result names the target host."""
    resolver = _Resolver({"app.example.com": ["10.0.0.5", "127.0.0.1"]})
    guard = AddressGuard("app.example.com", resolver=resolver)
    assert await guard.addresses("app.example.com", 443) == ["10.0.0.5", "127.0.0.1"]
    assert guard.notices() == AddressNotices(internal_target="app.example.com")
    assert address_warnings(guard.notices()) == [
        "the target host app.example.com is a public name but resolves only to internal "
        "addresses (loopback, private, link-local); the scan ran against them: check that "
        "this is the machine you meant to scan"
    ]


@pytest.mark.parametrize(
    ("host", "address"),
    [
        ("app.local", "10.0.0.5"),
        ("app.internal", "10.0.0.5"),
        ("svc.cluster.local", "10.0.0.5"),
        ("x.home.arpa", "192.168.1.10"),
        ("x.onion", "127.0.0.1"),
        ("x.test", "127.0.0.1"),
        ("app.notalistedlabel", "10.0.0.5"),
        ("app", "172.18.0.3"),
        ("localhost", "127.0.0.1"),
        ("10.0.0.5", "10.0.0.5"),
        ("::1", "::1"),
    ],
)
async def test_a_lab_cluster_or_address_target_resolving_inside_records_nothing(
    host: str, address: str
) -> None:
    """The common lab names, one label and IP literals are internal by choice: no warning."""
    guard = AddressGuard(host, resolver=_Resolver({host: [address]}))
    assert await guard.addresses(host, 8000) == [address]
    assert guard.notices() == AddressNotices()
    assert address_warnings(guard.notices()) == []


async def test_a_host_with_public_and_internal_addresses_is_reported_once() -> None:
    """
    The public ones are used and the host is named with the count it lost, the first time only.

    The host that resolves only to public addresses, asked in the same scan, is the control: it
    records nothing, so the record comes from the mixed answer and not from being asked.
    """
    resolver = _Resolver(
        {
            "www.example.com": [_PUBLIC],
            "api.example.com": [_PUBLIC, "10.0.0.1", _PUBLIC_2],
            "cdn.example.com": [_PUBLIC_2],
        }
    )
    guard = AddressGuard("www.example.com", resolver=resolver)
    assert await guard.addresses("www.example.com", 443) == [_PUBLIC]
    assert await guard.addresses("api.example.com", 443) == [_PUBLIC, _PUBLIC_2]
    assert await guard.addresses("API.example.com", 80) == [_PUBLIC, _PUBLIC_2]
    assert await guard.addresses("cdn.example.com", 443) == [_PUBLIC_2]
    assert guard.notices() == AddressNotices(left_out=(("api.example.com", 1),))
    assert address_warnings(guard.notices()) == [
        "api.example.com resolves to 1 internal address(es) besides its public ones; "
        "the scan used only the public addresses"
    ]


async def test_the_target_itself_with_internal_addresses_left_out_is_reported() -> None:
    """The target is a host the scan connects to, so its own mixed answer is named too."""
    resolver = _Resolver({"www.example.com": ["127.0.0.1", _PUBLIC, "fd00::1"]})
    guard = AddressGuard("www.example.com", resolver=resolver)
    assert await guard.addresses("www.example.com", 443) == [_PUBLIC]
    assert guard.notices() == AddressNotices(left_out=(("www.example.com", 2),))


async def test_a_host_resolving_only_inside_is_refused_and_records_nothing_new() -> None:
    """The refusal is the blocked-address warning's; the notices stay what they were."""
    resolver = _Resolver(
        {
            "www.example.com": [_PUBLIC],
            "api.example.com": [_PUBLIC, "10.0.0.1"],
            "intra.example.com": ["10.0.0.5", "127.0.0.1"],
        }
    )
    guard = AddressGuard("www.example.com", resolver=resolver)
    await guard.addresses("api.example.com", 443)
    before = guard.notices()
    assert before.left_out == (("api.example.com", 1),)
    with pytest.raises(BlockedAddressError):
        await guard.addresses("intra.example.com", 443)
    assert guard.notices() == before


async def test_the_hosts_past_the_cap_are_one_summary_line() -> None:
    """Twelve hosts with addresses left out give ten named lines and one line for the other two."""
    hosts = [f"h{n:02}.example.com" for n in range(12)]
    table = {host: [_PUBLIC, "10.0.0.1"] for host in hosts}
    table["www.example.com"] = [_PUBLIC]
    guard = AddressGuard("www.example.com", resolver=_Resolver(table))
    for host in hosts:
        await guard.addresses(host, 443)
    lines = address_warnings(guard.notices())
    assert MAX_LEFT_OUT_LINES == 10
    assert len(lines) == 11
    assert [line.split(" ", 1)[0] for line in lines[:10]] == hosts[:10]
    assert lines[10] == "2 more host(s) resolve to internal addresses besides their public ones"


def test_exactly_the_cap_names_every_host_and_adds_no_summary() -> None:
    """At the cap every host has its own line; the summary line starts one host past it."""
    left_out = tuple((f"h{n}.example.com", 1) for n in range(MAX_LEFT_OUT_LINES))
    lines = address_warnings(AddressNotices(left_out=left_out))
    assert len(lines) == MAX_LEFT_OUT_LINES
    assert not any("more host(s)" in line for line in lines)


def test_both_notices_give_the_target_line_first() -> None:
    """The internal target leads, then the hosts in the order they were first asked for."""
    lines = address_warnings(
        AddressNotices(internal_target="app.example.com", left_out=(("a.example.com", 3),))
    )
    assert len(lines) == 2
    assert lines[0].startswith("the target host app.example.com ")
    assert lines[1].startswith("a.example.com resolves to 3 internal address(es) ")


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
    with pytest.raises(httpcore2.ConnectError):
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
    with pytest.raises(httpcore2.ConnectTimeout):
        await backend.connect_tcp("www.example.com", 443, timeout=0.05)


def test_install_refuses_a_layout_it_does_not_know() -> None:
    """Without the expected httpx2 internals the scan fails loudly instead of running unguarded."""
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
    assert result.error == (
        "BlockedAddressError: the host resolves to an address the scan may not reach"
    )


async def test_the_httpx2_error_keeps_the_guard_refusal_as_its_cause() -> None:
    """The client tells a refusal apart through the cause ``httpx2`` keeps on its own error."""
    resolver = _Resolver({"www.example.com": [_PUBLIC], "intra.example.com": ["10.0.0.5"]})
    transport = httpx2.AsyncHTTPTransport()
    install(transport, AddressGuard("www.example.com", resolver=resolver))
    async with httpx2.AsyncClient(transport=transport) as client:
        with pytest.raises(httpx2.ConnectError) as caught:
            await client.get("https://intra.example.com/")
    assert isinstance(caught.value.__cause__, BlockedAddressError)
