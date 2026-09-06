"""Active-injection checks (spec 006): reflected XSS, SQLi, path traversal, open redirect.

The crafted-request work runs in ``engine.InjectionScanner`` (an orchestrator pass, ADR-1);
the check classes in ``checks`` filter its ``InjectionHit``s by ``kind`` into findings.
"""

from __future__ import annotations

from webvigil.checks.injection import checks  # noqa: F401  (registers the six checks)
