"""
TLS/HTTPS checks (RF-19).

Importing this package registers the combined TLS/HTTPS check.
"""

from __future__ import annotations

from webvigil.checks.tls import check  # noqa: F401
