"""X.509 certificate inspection for the TLS/HTTPS check."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from webvigil.core.findings import Severity

_EXPIRY_WARNING = timedelta(days=14)
_WEAK_HASHES = {"md5", "sha1"}


@dataclass(frozen=True, slots=True)
class CertIssue:
    dedup_key: str
    severity: Severity
    title: str
    description: str


def _matches(pattern: str, host: str) -> bool:
    pattern = pattern.lower().strip()
    host = host.lower().strip()
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and host.count(".") == pattern.count(".")
    return False


def analyze(cert_der: bytes, host: str, *, now: datetime | None = None) -> list[CertIssue]:
    """Return the certificate problems relevant to ``host``."""
    now = now or datetime.now(UTC)
    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except ValueError:
        return [
            CertIssue(
                "cert-unparseable",
                Severity.MEDIUM,
                "TLS certificate could not be parsed",
                "The server presented a certificate WebVigil could not decode.",
            )
        ]

    issues: list[CertIssue] = []

    if cert.not_valid_after_utc < now:
        issues.append(
            CertIssue(
                "cert-expired",
                Severity.HIGH,
                "TLS certificate has expired",
                f"The certificate expired on {cert.not_valid_after_utc.date()}.",
            )
        )
    elif cert.not_valid_after_utc - now < _EXPIRY_WARNING:
        issues.append(
            CertIssue(
                "cert-expiring-soon",
                Severity.MEDIUM,
                "TLS certificate expires soon",
                f"The certificate expires on {cert.not_valid_after_utc.date()}.",
            )
        )
    if cert.not_valid_before_utc > now:
        issues.append(
            CertIssue(
                "cert-not-yet-valid",
                Severity.HIGH,
                "TLS certificate is not yet valid",
                f"The certificate becomes valid on {cert.not_valid_before_utc.date()}.",
            )
        )

    names = _san_dns_names(cert)
    if names and not any(_matches(name, host) for name in names):
        issues.append(
            CertIssue(
                "cert-hostname-mismatch",
                Severity.HIGH,
                "TLS certificate does not cover the requested host",
                f"The certificate is valid for {', '.join(names)} but not {host}.",
            )
        )

    algorithm = cert.signature_hash_algorithm
    if algorithm is not None and algorithm.name.lower() in _WEAK_HASHES:
        issues.append(
            CertIssue(
                "cert-weak-signature",
                Severity.MEDIUM,
                f"TLS certificate uses a weak signature ({algorithm.name})",
                "Certificates signed with MD5 or SHA-1 are forgeable and rejected by browsers.",
            )
        )

    if cert.issuer == cert.subject:
        issues.append(
            CertIssue(
                "cert-self-signed",
                Severity.MEDIUM,
                "TLS certificate is self-signed",
                "A self-signed certificate provides no third-party identity assurance.",
            )
        )

    return issues


def _san_dns_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    san = ext.value
    assert isinstance(san, x509.SubjectAlternativeName)
    return list(san.get_values_for_type(x509.DNSName))
