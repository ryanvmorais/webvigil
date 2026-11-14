"""
The certificate analysis of the TLS check, on DER built in memory.

Each test builds a self-signed certificate with ``cryptography`` and, where needed, edits its
DER bytes: no socket, no TLS handshake. The handshake path is covered by ``test_checks_tls.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from webvigil.checks.tls._cert import analyze

# ecdsa-with-SHA256 (1.2.840.10045.4.3.2) as a DER OID, and the same OID with its last arc
# changed to one no library knows: same length, so the rest of the DER stays valid.
_ECDSA_SHA256 = bytes.fromhex("06082A8648CE3D040302")
_UNKNOWN_SIG = bytes.fromhex("06082A8648CE3D04037F")


def _der(host: str = "example.com") -> bytes:
    """
    Args:
        host (str): The subject and only SAN name. Defaults to ``"example.com"``.

    Returns:
        bytes: A valid, self-signed ECDSA certificate for ``host``, valid for 90 days.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_a_valid_self_signed_certificate_is_only_self_signed() -> None:
    """The baseline: a fresh certificate for the host reports self-signing and nothing else."""
    assert [issue.dedup_key for issue in analyze(_der(), "example.com")] == ["cert-self-signed"]


def test_bytes_that_are_not_der_are_unparseable() -> None:
    """DER that does not load is one ``cert-unparseable`` issue."""
    assert [issue.dedup_key for issue in analyze(b"not a certificate", "example.com")] == [
        "cert-unparseable"
    ]


def test_an_unknown_signature_oid_is_unparseable_not_a_crash() -> None:
    """The DER loads, but reading the signature hash raises: still ``cert-unparseable``."""
    der = _der()
    assert der.count(_ECDSA_SHA256) == 2  # the TBS and the outer signature algorithm
    tampered = der.replace(_ECDSA_SHA256, _UNKNOWN_SIG)
    assert [issue.dedup_key for issue in analyze(tampered, "example.com")] == ["cert-unparseable"]
