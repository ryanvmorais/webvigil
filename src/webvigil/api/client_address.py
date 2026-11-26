"""
Who is really on the other end of a request, for the login limits.

The address of the connection is the only one a client cannot choose. ``X-Forwarded-For`` is read
only when that connection comes from a proxy listed in ``web.trusted_proxies``, and then from the
right, because each proxy appends the address it saw: everything to the left of the last trusted
hop was written by the client. ``X-Forwarded-Host`` says nothing about who is asking and is never
read here.

An entry of ``trusted_proxies`` may be a name, because a Compose service has no fixed address: the
name is resolved when it is needed and again after ``NAME_TTL_S``, so a recreated container is
recognized without a restart of the API. One lookup runs at a time, and the requests that arrive
during it use its answer.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from collections.abc import Callable, Iterable, Sequence

type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# How long a resolved proxy name is believed. Short, so a recreated container is trusted soon and
# its old address stops being trusted just as soon.
NAME_TTL_S = 30.0
# One IPv6 subscriber usually gets a whole /64, so a longer key would hand a single client a new
# address for every attempt. Whoever holds several /64 networks still counts as several clients.
_IPV6_CLIENT_PREFIX = 64


def parse_address(text: str) -> IPAddress | None:
    """
    Args:
        text (str): An address as a server or a proxy reports it.

    Returns:
        IPAddress | None: The address, with an IPv4-mapped IPv6 address (how a dual-stack socket
            reports an IPv4 peer) unwrapped to IPv4; ``None`` when ``text`` is not an address.
    """
    try:
        address = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _resolve_name(name: str) -> frozenset[IPAddress]:
    """
    Args:
        name (str): A host name from ``trusted_proxies``.

    Returns:
        frozenset[IPAddress]: Its current addresses; empty when it does not resolve, which trusts
            nobody (in Compose the API starts before the dashboard's name exists).
    """
    try:
        results = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return frozenset()
    parsed = (parse_address(str(result[4][0])) for result in results)
    return frozenset(address for address in parsed if address is not None)


class TrustedProxies:
    """The proxies whose ``X-Forwarded-For`` is believed: networks, and names resolved on demand."""

    def __init__(
        self,
        entries: Iterable[str] = (),
        *,
        resolve: Callable[[str], frozenset[IPAddress]] = _resolve_name,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """
        Args:
            entries (Iterable[str]): Validated ``trusted_proxies`` entries. Defaults to none.
            resolve (Callable[[str], frozenset[IPAddress]]): Turns a name into its addresses.
                Injectable so tests use no DNS. Defaults to the system resolver.
            clock (Callable[[], float]): A monotonic clock in seconds. Injectable so tests do
                not sleep. Defaults to :func:`time.monotonic`.
        """
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._names: list[str] = []
        for entry in entries:
            try:
                self._networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                self._names.append(entry)
        self._resolve = resolve
        self._clock = clock
        # Replaced as one tuple, so a reader without the lock sees the old answer or the new one.
        # The lock lets one thread resolve after the expiry while the others wait for its answer.
        self._resolved: tuple[float, frozenset[IPAddress]] | None = None
        self._refresh = threading.Lock()

    def __contains__(self, address: IPAddress) -> bool:
        """
        Args:
            address (IPAddress): The address to check.

        Returns:
            bool: ``True`` when it is in a listed network or is a listed name's current address.
        """
        if any(address in network for network in self._networks):
            return True
        return bool(self._names) and address in self._name_addresses()

    def _name_addresses(self) -> frozenset[IPAddress]:
        """
        Returns:
            frozenset[IPAddress]: The current addresses of every listed name.
        """
        resolved = self._resolved
        if resolved is not None and self._clock() < resolved[0]:
            return resolved[1]
        with self._refresh:
            # Checked again: another thread may have resolved while this one waited for the lock.
            now = self._clock()
            resolved = self._resolved
            if resolved is not None and now < resolved[0]:
                return resolved[1]
            addresses = frozenset().union(*(self._resolve(name) for name in self._names))
            self._resolved = (now + NAME_TTL_S, addresses)
            return addresses


def client_address(peer: str | None, forwarded_for: Sequence[str], trusted: TrustedProxies) -> str:
    """
    Name the client a request counts against.

    Args:
        peer (str | None): The address of the connection; ``None`` when the server has none.
        forwarded_for (Sequence[str]): Every ``X-Forwarded-For`` header value, in order.
        trusted (TrustedProxies): The proxies whose word is taken.

    Returns:
        str: The first address, walking from the connection to the left, that is not a trusted
            proxy, with an IPv6 client named by its /64. A hop that is not an address ends the walk
            at the proxy that reported it, so garbage cannot mint a fresh key. A peer that is not
            an address is returned as it is, and no peer is ``"unknown"``.
    """
    if peer is None:
        return "unknown"
    current = parse_address(peer)
    if current is None:
        return peer
    hops = [hop for value in forwarded_for for hop in value.split(",")]
    for hop in reversed(hops):
        if current not in trusted:
            break
        previous = parse_address(hop)
        if previous is None:
            break
        current = previous
    if isinstance(current, ipaddress.IPv6Address):
        return str(ipaddress.ip_network((int(current), _IPV6_CLIENT_PREFIX), strict=False))
    return str(current)
