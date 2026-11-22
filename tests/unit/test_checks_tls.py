"""
TLS/HTTPS check: certificate, redirect, and mixed-content findings — RF-19.

The certificate cases run against a real localhost TLS listener from the
``tls_server`` fixture, serving a leaf issued by the session ``tls_ca`` — so the
probe does a genuine handshake. The HTTP-only case points at a dead port.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import UTC, datetime, timedelta

import pytest
import trustme

from tests.support import make_context, make_page
from webvigil.checks.tls import _cert
from webvigil.checks.tls.check import TlsHttpsCheck
from webvigil.core.config import ScanConfig
from webvigil.core.findings import Severity
from webvigil.core.target import Target
from webvigil.http import tls_probe
from webvigil.http.client import HttpClient

_ServerFactory = Callable[..., AbstractContextManager]


def _ctx(port: int, *, scheme: str = "https", text: str = "<html></html>"):
    """
    Build a scan context targeting ``127.0.0.1:<port>``.

    Args:
        port (int): The port the TLS server (or nothing) is listening on.
        scheme (str): ``"https"`` or ``"http"``. Defaults to ``"https"``.
        text (str): The entry page body, for the mixed-content case.

    Returns:
        ScanContext: The context, wired to a real HTTP client.
    """
    url = f"{scheme}://127.0.0.1:{port}/"
    http = HttpClient(Target.parse(url), ScanConfig())
    return make_context(make_page(url=url, text=text), target_url=url, http=http)


async def test_healthy_certificate_produces_no_cert_findings(
    tls_server: _ServerFactory, tls_ca: trustme.CA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A valid, in-name certificate is analysed and yields no ``certificate`` findings."""
    verdicts: list[list[_cert.CertIssue]] = []
    real_analyze = _cert.analyze

    def _recording(
        cert_der: bytes, host: str, *, now: datetime | None = None
    ) -> list[_cert.CertIssue]:
        issues = real_analyze(cert_der, host, now=now)
        verdicts.append(issues)
        return issues

    monkeypatch.setattr(_cert, "analyze", _recording)
    with tls_server(cert=tls_ca.issue_cert("127.0.0.1")) as server:
        findings = await TlsHttpsCheck().run(_ctx(server.port))
    # the handshake read the certificate and the analysis ran: "no finding" is its verdict
    assert verdicts == [[]]
    assert [f.fingerprint for f in findings if "cert" in f.location.key] == []


async def test_expired_certificate_is_flagged(
    tls_server: _ServerFactory, tls_ca: trustme.CA
) -> None:
    """A certificate whose validity window is entirely in the past is flagged as expired."""
    past = datetime.now(UTC) - timedelta(days=2)
    cert = tls_ca.issue_cert("127.0.0.1", not_before=past, not_after=past + timedelta(days=1))
    with tls_server(cert=cert) as server:
        findings = await TlsHttpsCheck().run(_ctx(server.port))
    assert any("expired" in f.title.lower() for f in findings)


async def test_hostname_mismatch_is_flagged(tls_server: _ServerFactory, tls_ca: trustme.CA) -> None:
    """A certificate whose SAN does not cover the target host is flagged."""
    with tls_server(cert=tls_ca.issue_cert("not-this-host.example")) as server:
        findings = await TlsHttpsCheck().run(_ctx(server.port))
    assert any("does not cover" in f.title for f in findings)


async def test_http_only_site_is_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    """A plaintext entry page with no HTTPS redirect is a page-level HIGH finding."""

    # The finding comes from the entry page alone; no TLS endpoint answers.
    async def _offline(*_args: object, **_kwargs: object) -> tls_probe.TlsProbeResult:
        return tls_probe._unreachable(OSError("offline test"))

    monkeypatch.setattr(tls_probe, "probe", _offline)
    findings = await TlsHttpsCheck().run(_ctx(59999, scheme="http"))
    (finding,) = findings
    assert finding.title == "Site is served over HTTP with no redirect to HTTPS"
    assert finding.location.key == "" and finding.severity is Severity.HIGH


async def test_mixed_content_is_flagged(tls_server: _ServerFactory, tls_ca: trustme.CA) -> None:
    """An HTTPS page pulling a sub-resource over ``http://`` is flagged as mixed content."""
    html = '<html><body><script src="http://cdn.example/x.js"></script></body></html>'
    with tls_server(cert=tls_ca.issue_cert("127.0.0.1")) as server:
        findings = await TlsHttpsCheck().run(_ctx(server.port, text=html))
    assert any("plaintext HTTP" in f.title for f in findings)
