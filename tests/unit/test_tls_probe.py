"""TLS probe: version detection and certificate retrieval — RF-19."""

from __future__ import annotations

import ssl
from collections.abc import Callable
from contextlib import AbstractContextManager

from webvigil.http.tls_probe import OK, REFUSED, probe

_ServerFactory = Callable[..., AbstractContextManager[object]]


async def test_probe_reports_versions_and_certificate(tls_server: _ServerFactory) -> None:
    with tls_server(max_version=ssl.TLSVersion.TLSv1_2) as server:
        result = await probe(server.host, server.port, timeout=3)  # type: ignore[attr-defined]

    assert result.reachable is True
    assert result.negotiated_version == "TLSv1.2"
    assert result.offered_versions["TLSv1.2"] == OK
    assert result.offered_versions["TLSv1.3"] == REFUSED
    assert result.peer_cert_der is not None


async def test_probe_on_dead_port_is_unreachable() -> None:
    result = await probe("127.0.0.1", 1, timeout=1)
    assert result.reachable is False
    assert result.error is not None
    assert result.negotiated_version is None
