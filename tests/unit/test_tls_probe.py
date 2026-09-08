"""
TLS probe: version detection and certificate retrieval — RF-19.

Runs against a real in-process TLS server (the ``tls_server`` fixture in
``tests/conftest.py``, backed by a ``trustme`` CA), so the probe does a genuine
handshake per offered version and reads a genuine peer certificate.
"""

from __future__ import annotations

import ssl
from collections.abc import Callable
from contextlib import AbstractContextManager

from webvigil.http.tls_probe import OK, REFUSED, probe

_ServerFactory = Callable[..., AbstractContextManager[object]]


async def test_probe_reports_versions_and_certificate(tls_server: _ServerFactory) -> None:
    """Against a TLS 1.2-capped server the probe reports 1.2 negotiated, 1.3 refused, and a cert."""
    with tls_server(max_version=ssl.TLSVersion.TLSv1_2) as server:
        result = await probe(server.host, server.port, timeout=3)  # type: ignore[attr-defined]

    assert result.reachable is True
    assert result.negotiated_version == "TLSv1.2"
    assert result.offered_versions["TLSv1.2"] == OK
    assert result.offered_versions["TLSv1.3"] == REFUSED
    assert result.peer_cert_der is not None


async def test_probe_on_dead_port_is_unreachable() -> None:
    """A closed port comes back unreachable, with an error and no negotiated version."""
    result = await probe("127.0.0.1", 1, timeout=1)
    assert result.reachable is False
    assert result.error is not None
    assert result.negotiated_version is None
