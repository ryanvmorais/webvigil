"""
CORS misconfiguration check (RF-20).

Importing this package registers the CORS check.
"""

from __future__ import annotations

from webvigil.checks.cors import check  # noqa: F401
