"""
The address guard: which network addresses a scan may connect to.

The scope guard decides by name; this module decides by address. Every host name is resolved
once per scan and the connection goes to the address that was checked, so a name cannot point
somewhere else halfway through a scan. When the target resolves to a public address, no host of
the scan may resolve to a loopback, private, link-local or other non-public address: a site on
the internet never sends the scanner into the network it runs on. A target that resolves only to
non-public addresses (``localhost``, a Compose service, an intranet host) was chosen by the user,
so its scan may reach them.

When an HTTP proxy is set in the environment (``HTTP_PROXY`` / ``HTTPS_PROXY``), ``httpx``
connects to the proxy and the proxy resolves the names: the check does not apply there.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Iterable

import httpcore

# Resolves ``(host, port)`` to the IP addresses a connection may use, in preference order.
Resolver = Callable[[str, int], Awaitable[list[str]]]

# RFC 6052's well-known NAT64 prefix carries an IPv4 address in its last 32 bits.
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")


class BlockedAddressError(httpcore.ConnectError):
    """A host of the scan resolved only to addresses the scan may not connect to."""


def _embedded_ipv4(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """
    Args:
        address (ipaddress.IPv6Address): An IPv6 address.

    Returns:
        ipaddress.IPv4Address | None: The IPv4 address it carries (mapped, 6to4, Teredo client
            or NAT64), or ``None``.
    """
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if address.sixtofour is not None:
        return address.sixtofour
    if address.teredo is not None:
        return address.teredo[1]
    if address in _NAT64:
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return None


def is_public(address: str) -> bool:
    """
    Whether ``address`` is a globally reachable unicast address.

    Args:
        address (str): An IPv4 or IPv6 address, as a resolver returns it (an IPv6 zone id is
            allowed).

    Returns:
        bool: ``False`` for loopback, private, link-local, shared, reserved, multicast and
            unspecified addresses, for an IPv6 address that carries one of them, and for a
            string that is not an address.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.scope_id is not None:
            return False
        inner = _embedded_ipv4(ip)
        if inner is not None:
            return is_public(str(inner))
    return ip.is_global and not ip.is_multicast


async def system_resolver(host: str, port: int) -> list[str]:
    """
    Resolve ``host`` with the operating system's resolver.

    Args:
        host (str): A host name or an IP literal.
        port (int): The port the connection will use.

    Returns:
        list[str]: The distinct addresses, in the resolver's order.

    Raises:
        httpcore.ConnectError: When the name does not resolve.
    """
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise httpcore.ConnectError(f"{host}: {exc}") from exc
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


class AddressGuard:
    """
    The per-scan record of which addresses each host name may use.

    One instance lives for one scan: resolutions are cached and never refreshed.
    """

    def __init__(self, target_host: str, *, resolver: Resolver | None = None) -> None:
        """
        Args:
            target_host (str): The target host, as :attr:`~webvigil.core.target.Target.host`.
            resolver (Resolver | None): Test seam; the system resolver when ``None``.
        """
        self._target_host = target_host
        self._resolve = resolver or system_resolver
        self._lock = asyncio.Lock()
        self._pinned: dict[str, list[str]] = {}
        self._public_only: bool | None = None

    async def _pin(self, host: str, port: int) -> list[str]:
        """
        Args:
            host (str): A host name or IP literal.
            port (int): The port the connection will use.

        Returns:
            list[str]: Every address ``host`` resolved to the first time it was asked for.
        """
        if host not in self._pinned:
            self._pinned[host] = await self._resolve(host, port)
        return self._pinned[host]

    async def addresses(self, host: str, port: int) -> list[str]:
        """
        The addresses a connection to ``host`` may use.

        Args:
            host (str): A host name or IP literal (an IPv6 literal without brackets).
            port (int): The port the connection will use.

        Returns:
            list[str]: The allowed addresses, in the resolver's order, never empty.

        Raises:
            BlockedAddressError: When ``host`` resolved to no address the scan may use.
            httpcore.ConnectError: When a name does not resolve.
        """
        host = host.lower()
        async with self._lock:
            if self._public_only is None:
                target = await self._pin(self._target_host, port)
                self._public_only = any(is_public(a) for a in target)
            resolved = await self._pin(host, port)
        allowed = [a for a in resolved if is_public(a)] if self._public_only else resolved
        if not allowed:
            raise BlockedAddressError(
                f"{host} resolves to no public address; the target resolves to a public one, "
                "so the scan does not connect to internal addresses"
            )
        return allowed


class GuardedBackend(httpcore.AsyncNetworkBackend):
    """
    An ``httpcore`` network backend that connects only to the addresses an :class:`AddressGuard`
    allows.
    """

    def __init__(
        self, guard: AddressGuard, inner: httpcore.AsyncNetworkBackend | None = None
    ) -> None:
        """
        Args:
            guard (AddressGuard): The scan's address guard.
            inner (httpcore.AsyncNetworkBackend | None): The backend that opens the sockets;
                ``httpcore.AnyIOBackend`` when ``None``.
        """
        self._guard = guard
        self._inner = inner or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        """
        Connect to the first allowed address of ``host`` that answers.

        TLS still verifies the certificate against ``host``: ``httpcore`` passes the request's
        host name as the server name, whatever address the socket uses.

        Args:
            host (str): The host the request names.
            port (int): The port.
            timeout (float | None): The connect timeout, applied to the resolution too.
            local_address (str | None): The local address to bind.
            socket_options (Iterable[httpcore.SOCKET_OPTION] | None): Socket options.

        Returns:
            httpcore.AsyncNetworkStream: The connected stream.

        Raises:
            BlockedAddressError: When ``host`` resolved to no address the scan may use.
            httpcore.ConnectError: When no allowed address accepts the connection.
            httpcore.ConnectTimeout: When the resolution or the connection times out.
        """
        try:
            async with asyncio.timeout(timeout):
                allowed = await self._guard.addresses(host, port)
        except TimeoutError as exc:
            raise httpcore.ConnectTimeout(f"{host}: name resolution timed out") from exc
        options = list(socket_options or [])
        last: Exception | None = None
        for address in allowed:
            try:
                return await self._inner.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last = exc
        assert last is not None  # ``allowed`` is never empty
        raise last

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:  # pragma: no cover - the scan never uses a Unix socket
        """
        Args:
            path (str): The socket path.
            timeout (float | None): The connect timeout.
            socket_options (Iterable[httpcore.SOCKET_OPTION] | None): Socket options.

        Returns:
            httpcore.AsyncNetworkStream: The connected stream.
        """
        return await self._inner.connect_unix_socket(path, timeout, socket_options)

    async def sleep(self, seconds: float) -> None:
        """
        Args:
            seconds (float): How long to sleep.
        """
        await self._inner.sleep(seconds)


def install(client_transport: object, guard: AddressGuard) -> None:
    """
    Route the connections of an ``httpx`` default transport through ``guard``.

    ``httpx`` has no public option for the network backend, and passing a custom transport to
    ``AsyncClient`` turns off the proxies set in the environment, so the backend is swapped on
    the client's own transport. A layout this code does not recognise is an error, never a
    silent scan without the guard.

    Args:
        client_transport (object): ``httpx.AsyncClient._transport`` of a client built without a
            custom transport.
        guard (AddressGuard): The scan's address guard.

    Raises:
        RuntimeError: When the transport is not the ``httpx``/``httpcore`` layout expected.
    """
    pool = getattr(client_transport, "_pool", None)
    if not isinstance(pool, httpcore.AsyncConnectionPool) or not hasattr(pool, "_network_backend"):
        raise RuntimeError("unexpected httpx transport layout: cannot install the address guard")
    pool._network_backend = GuardedBackend(guard)


__all__ = [
    "AddressGuard",
    "BlockedAddressError",
    "GuardedBackend",
    "Resolver",
    "install",
    "is_public",
    "system_resolver",
]
