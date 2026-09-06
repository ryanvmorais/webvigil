"""TLS/HTTPS check: certificate, redirect, and mixed-content findings — RF-19."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import UTC, datetime, timedelta

import trustme

from tests.support import make_context, make_page
from webvigil.checks.tls.check import TlsHttpsCheck
from webvigil.core.config import ScanConfig
from webvigil.core.target import Target
from webvigil.http.client import HttpClient

_ServerFactory = Callable[..., AbstractContextManager]


def _ctx(port: int, *, scheme: str = "https", text: str = "<html></html>"):
    url = f"{scheme}://127.0.0.1:{port}/"
    http = HttpClient(Target.parse(url), ScanConfig())
    return make_context(make_page(url=url, text=text), target_url=url, http=http)


async def test_healthy_certificate_produces_no_cert_findings(
    tls_server: _ServerFactory, tls_ca: trustme.CA
) -> None:
    with tls_server(cert=tls_ca.issue_cert("127.0.0.1")) as server:
        findings = await TlsHttpsCheck().run(_ctx(server.port))
    assert [f.fingerprint for f in findings if "cert" in f.location.key] == []


async def test_expired_certificate_is_flagged(
    tls_server: _ServerFactory, tls_ca: trustme.CA
) -> None:
    past = datetime.now(UTC) - timedelta(days=2)
    cert = tls_ca.issue_cert("127.0.0.1", not_before=past, not_after=past + timedelta(days=1))
    with tls_server(cert=cert) as server:
        findings = await TlsHttpsCheck().run(_ctx(server.port))
    assert any("expired" in f.title.lower() for f in findings)


async def test_hostname_mismatch_is_flagged(tls_server: _ServerFactory, tls_ca: trustme.CA) -> None:
    with tls_server(cert=tls_ca.issue_cert("not-this-host.example")) as server:
        findings = await TlsHttpsCheck().run(_ctx(server.port))
    assert any("does not cover" in f.title for f in findings)


async def test_http_only_site_is_flagged() -> None:
    # Nothing listens on this port; the entry page is plain HTTP.
    findings = await TlsHttpsCheck().run(_ctx(59999, scheme="http"))
    assert any(f.location.key == "" and "HTTP" in f.title for f in findings)


async def test_mixed_content_is_flagged(tls_server: _ServerFactory, tls_ca: trustme.CA) -> None:
    html = '<html><body><script src="http://cdn.example/x.js"></script></body></html>'
    with tls_server(cert=tls_ca.issue_cert("127.0.0.1")) as server:
        findings = await TlsHttpsCheck().run(_ctx(server.port, text=html))
    assert any("plaintext HTTP" in f.title for f in findings)
