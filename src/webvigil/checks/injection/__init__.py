"""
Active-injection checks (spec 006): reflected XSS, SQLi, path traversal, open redirect,
plus SSRF (spec 009) and stored XSS (spec 008).

The crafted-request work runs in
:class:`~webvigil.checks.injection.engine.InjectionScanner` (an orchestrator
pass, ADR-1); the check classes in :mod:`webvigil.checks.injection.checks`
filter its ``InjectionHit``s by ``kind`` into findings.
"""

from __future__ import annotations

from webvigil.checks.injection import checks  # noqa: F401  (registers the six checks)
