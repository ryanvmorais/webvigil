"""Dependency fingerprinting: passive client-side library detection + advisory matching.

Spec 004. The :class:`~webvigil.checks.deps.fingerprint.Fingerprinter` runs as a pass in the
orchestrator (not as a check) and its detections are consumed by two checks:

- ``deps.js.vulnerable-library`` — a finding per detected library version with a known
  advisory in the vendored Retire.js database.
- ``deps.js.library-detected`` — an INFO finding per recognised library whose version could
  not be determined.

Disabling both check ids also disables the fingerprint pass (ADR-3).
"""

from __future__ import annotations

from webvigil.checks.deps import check  # noqa: F401  — runs the @register calls
