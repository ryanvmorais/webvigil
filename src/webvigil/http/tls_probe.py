"""Stdlib-only TLS inspection: per-version handshake probing and the peer certificate.

Deliberately small (ADR-8): version detection and the raw certificate, nothing about cipher
suites. The blocking socket work runs in a worker thread and holds a rate-limiter slot.
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
    reachable: bool
    negotiated_version: str | None
    offered_versions: dict[str, str]
    peer_cert_der: bytes | None
    error: str | None = None


def _unverified_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _handshake(host: str, port: int, timeout: float, context: ssl.SSLContext) -> ssl.SSLSocket:
    raw_sock = socket.create_connection((host, port), timeout=timeout)
    return context.wrap_socket(raw_sock, server_hostname=host)


def _probe_version(host: str, port: int, timeout: float, version: ssl.TLSVersion) -> str:
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
    """Probe ``host:port`` for offered TLS versions and its certificate."""
    if limiter is not None:
        async with limiter.slot(host):
            return await asyncio.to_thread(_probe_sync, host, port, timeout)
    return await asyncio.to_thread(_probe_sync, host, port, timeout)
