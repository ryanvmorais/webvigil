"""
Stdlib-only TLS inspection: per-version handshake probing and the peer certificate.

Deliberately small (ADR-8): version detection and the raw certificate, nothing
about cipher suites. The blocking socket work runs in a worker thread and holds
a rate-limiter slot.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import warnings
from dataclasses import dataclass

from webvigil.http.policy import RateLimiter

_DEFAULT_TIMEOUT = 10.0

# Ordered oldest → newest.
_VERSIONS: dict[str, ssl.TLSVersion] = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

# Per-version probe outcomes.
OK = "ok"
REFUSED = "refused"
UNAVAILABLE = "unavailable"  # this client's OpenSSL cannot even attempt the version


@dataclass(frozen=True, slots=True)
class TlsProbeResult:
    """
    The outcome of probing one ``host:port`` for its TLS support.

    Attributes:
        reachable (bool): ``True`` when at least the initial handshake
            succeeded.
        negotiated_version (str | None): TLS version the server chose when left
            to its own preference, or ``None`` when unreachable.
        offered_versions (dict[str, str]): Per-version outcome, keyed by the
            names in ``_VERSIONS``; each value is ``OK``, ``REFUSED``, or
            ``UNAVAILABLE``.
        peer_cert_der (bytes | None): The peer certificate in DER form, or
            ``None`` when unreachable.
        error (str | None): ``"<ExceptionType>: <message>"`` when the initial
            handshake failed, else ``None``.
    """

    reachable: bool
    negotiated_version: str | None
    offered_versions: dict[str, str]
    peer_cert_der: bytes | None
    error: str | None = None


def _unverified_context() -> ssl.SSLContext:
    """
    Build an SSL context that skips hostname and chain verification.

    The check inspects what the server offers; certificate validity is a
    separate concern handled by the TLS check itself.

    Returns:
        ssl.SSLContext: A client context with verification disabled.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _handshake(host: str, port: int, timeout: float, context: ssl.SSLContext) -> ssl.SSLSocket:
    """
    Open a TCP connection and wrap it in TLS.

    Args:
        host (str): Target host.
        port (int): Target port.
        timeout (float): Connect timeout in seconds.
        context (ssl.SSLContext): The context to wrap the socket with.

    Returns:
        ssl.SSLSocket: The connected TLS socket (the caller closes it).
    """
    raw_sock = socket.create_connection((host, port), timeout=timeout)
    return context.wrap_socket(raw_sock, server_hostname=host)


def _probe_version(host: str, port: int, timeout: float, version: ssl.TLSVersion) -> str:
    """
    Attempt a handshake pinned to exactly one TLS version.

    Args:
        host (str): Target host.
        port (int): Target port.
        timeout (float): Connect timeout in seconds.
        version (ssl.TLSVersion): The single version to allow.

    Returns:
        str: ``UNAVAILABLE`` when this client's OpenSSL cannot attempt the
            version, ``OK`` when the server completed the handshake, ``REFUSED``
            otherwise.
    """
    context = _unverified_context()
    try:
        with warnings.catch_warnings():
            # We intentionally test legacy versions; the deprecation notice is expected.
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = version
            context.maximum_version = version
    except ValueError:
        return UNAVAILABLE
    try:
        with _handshake(host, port, timeout, context):
            return OK
    except ssl.SSLError:
        return REFUSED
    except (TimeoutError, OSError):
        return REFUSED


def _probe_sync(host: str, port: int, timeout: float) -> TlsProbeResult:
    """
    Blocking implementation of :func:`probe`, meant to run in a worker thread.

    Does one open-ended handshake to capture the negotiated version and the
    certificate, then one pinned handshake per known version.

    Args:
        host (str): Target host.
        port (int): Target port.
        timeout (float): Connect timeout in seconds.

    Returns:
        TlsProbeResult: The gathered result; ``reachable=False`` with ``error``
            set when the first handshake fails.
    """
    negotiated: str | None = None
    cert_der: bytes | None = None
    try:
        with _handshake(host, port, timeout, _unverified_context()) as tls_sock:
            negotiated = tls_sock.version()
            cert_der = tls_sock.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        return TlsProbeResult(
            reachable=False,
            negotiated_version=None,
            offered_versions=dict.fromkeys(_VERSIONS, UNAVAILABLE),
            peer_cert_der=None,
            error=f"{type(exc).__name__}: {exc}",
        )

    offered = {
        name: _probe_version(host, port, timeout, version) for name, version in _VERSIONS.items()
    }
    return TlsProbeResult(
        reachable=True,
        negotiated_version=negotiated,
        offered_versions=offered,
        peer_cert_der=cert_der,
    )


async def probe(
    host: str,
    port: int = 443,
    *,
    limiter: RateLimiter | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> TlsProbeResult:
    """
    Probe ``host:port`` for offered TLS versions and its certificate.

    The blocking work is offloaded to a worker thread; when a ``limiter`` is
    given, a rate-limiter slot is held for the duration so the probe counts
    against the good-neighbour budget.

    Args:
        host (str): Target host.
        port (int): Target port. Defaults to 443.
        limiter (RateLimiter | None): The shared rate limiter, or ``None`` to
            skip rate limiting (tests).
        timeout (float): Connect timeout in seconds. Defaults to
            ``_DEFAULT_TIMEOUT``.

    Returns:
        TlsProbeResult: The gathered result.
    """
    if limiter is not None:
        async with limiter.slot(host):
            return await asyncio.to_thread(_probe_sync, host, port, timeout)
    return await asyncio.to_thread(_probe_sync, host, port, timeout)
