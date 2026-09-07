"""
TLS/HTTPS check: protocol versions, certificate, redirect, and mixed content (RF-19).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from webvigil.checks.base import Check
from webvigil.checks.registry import register
from webvigil.checks.tls import _cert
from webvigil.core.context import ScanContext
from webvigil.core.findings import Category, Confidence, EvidenceItem, Finding, Location, Severity
from webvigil.http import tls_probe

_LEGACY_VERSIONS = {"TLSv1": Severity.HIGH, "TLSv1.1": Severity.MEDIUM}
_MIXED_CONTENT_RE = re.compile(r"""(?:src|href)\s*=\s*["']http://[^"']+["']""", re.IGNORECASE)


@register
class TlsHttpsCheck(Check):
    """
    One check covering the target's transport security.

    Reports a plaintext site with no redirect to HTTPS, an accepted obsolete
    protocol (TLS 1.0 HIGH, TLS 1.1 MEDIUM), the certificate problems from
    :func:`webvigil.checks.tls._cert.analyze`, and an HTTPS page that pulls
    sub-resources over ``http://``.
    """

    id = "tls.https"
    name = "TLS and HTTPS configuration"
    category = Category.TLS
    default_severity = Severity.HIGH
    cwe = (319, 295)
    references = ("https://owasp.org/www-project-secure-headers/#transport-layer-security",)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; probes the origin's TLS
                endpoint via ``ctx.http.limiter`` and reads the entry page.

        Returns:
            list[Finding]: Every transport-security finding, possibly empty.
        """
        findings: list[Finding] = []
        entry = ctx.entry
        wanted_https = urlsplit(ctx.target.entry_url).scheme == "https"
        got_https = urlsplit(entry.url).scheme == "https"

        if not wanted_https and not got_https and entry.ok:
            findings.append(
                self.finding(
                    title="Site is served over HTTP with no redirect to HTTPS",
                    description=(
                        "The target responded over plaintext HTTP and did not redirect to HTTPS, "
                        "so all traffic can be read and modified in transit."
                    ),
                    remediation="Redirect every HTTP request to HTTPS and enable HSTS.",
                    location=Location(url=entry.url),
                    severity=Severity.HIGH,
                    dedup_key="no-https",
                    evidence=[EvidenceItem.of("request", f"GET {ctx.target.entry_url}")],
                )
            )

        host, port = _tls_endpoint(ctx.target.origin)
        probe = await tls_probe.probe(host, port, limiter=ctx.http.limiter)
        if probe.reachable:
            findings.extend(self._version_findings(host, probe))
            if probe.peer_cert_der is not None:
                findings.extend(self._cert_findings(host, probe.peer_cert_der))

        if got_https:
            findings.extend(self._mixed_content_findings(entry.url, entry.text))

        return findings

    def _version_findings(self, host: str, probe: tls_probe.TlsProbeResult) -> list[Finding]:
        """
        Args:
            host (str): The TLS host.
            probe (tls_probe.TlsProbeResult): The probe result.

        Returns:
            list[Finding]: One finding per accepted obsolete protocol version.
        """
        findings: list[Finding] = []
        for version, severity in _LEGACY_VERSIONS.items():
            if probe.offered_versions.get(version) == tls_probe.OK:
                findings.append(
                    self.finding(
                        title=f"Server accepts the obsolete {version} protocol",
                        description=(
                            f"{host} completed a handshake using {version}, which is deprecated "
                            "and has known cryptographic weaknesses."
                        ),
                        remediation="Disable TLS 1.0 and 1.1; require TLS 1.2 or newer.",
                        location=Location(url=f"https://{host}"),
                        severity=severity,
                        dedup_key=f"legacy-{version}",
                        evidence=[EvidenceItem.of("offered versions", str(probe.offered_versions))],
                    )
                )
        return findings

    def _cert_findings(self, host: str, cert_der: bytes) -> list[Finding]:
        """
        Args:
            host (str): The TLS host the certificate should cover.
            cert_der (bytes): The peer certificate in DER form.

        Returns:
            list[Finding]: One finding per :class:`~webvigil.checks.tls._cert.CertIssue`.
        """
        return [
            self.finding(
                title=issue.title,
                description=issue.description,
                remediation="Reissue or replace the certificate so it is valid, trusted, and "
                "covers this host.",
                location=Location(url=f"https://{host}", header="certificate"),
                severity=issue.severity,
                confidence=Confidence.HIGH,
                dedup_key=issue.dedup_key,
                evidence=[EvidenceItem.of("certificate", f"host={host}")],
            )
            for issue in _cert.analyze(cert_der, host)
        ]

    def _mixed_content_findings(self, url: str, html: str) -> list[Finding]:
        """
        Args:
            url (str): The HTTPS page URL.
            html (str): Its body.

        Returns:
            list[Finding]: A single MEDIUM finding listing up to ten
                ``http://`` sub-resource references, or empty when there are
                none.
        """
        matches = _MIXED_CONTENT_RE.findall(html)
        if not matches:
            return []
        return [
            self.finding(
                title="HTTPS page references sub-resources over plaintext HTTP",
                description=(
                    "The page loads scripts, styles, or other resources over http://, which an "
                    "attacker can tamper with and which browsers may block."
                ),
                remediation="Load every sub-resource over HTTPS (or protocol-relative URLs).",
                location=Location(url=url),
                severity=Severity.MEDIUM,
                dedup_key="mixed-content",
                evidence=[EvidenceItem.of("references", "\n".join(matches[:10]))],
            )
        ]


def _tls_endpoint(origin: str) -> tuple[str, int]:
    """
    Args:
        origin (str): The target origin (scheme + host + optional port).

    Returns:
        tuple[str, int]: The host and port to probe, defaulting the port to 443.
    """
    parts = urlsplit(origin)
    return parts.hostname or "", parts.port or 443
