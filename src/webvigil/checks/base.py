"""The check plugin contract (RF-08).

A check subclasses :class:`Check`, sets its class-level metadata, and implements
``async run(ctx) -> list[Finding]``. Use :meth:`Check.finding` to build findings so the
``check_id``, CWE list, references, and fingerprint are filled in consistently.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import ClassVar

from webvigil.core.context import ScanContext
from webvigil.core.findings import (
    Category,
    Confidence,
    EvidenceItem,
    Finding,
    Location,
    ScanMode,
    Severity,
    compute_fingerprint,
)


class Check(ABC):
    """Base class for all checks."""

    id: ClassVar[str]
    name: ClassVar[str]
    category: ClassVar[Category]
    mode: ClassVar[ScanMode] = ScanMode.PASSIVE
    default_severity: ClassVar[Severity]
    cwe: ClassVar[tuple[int, ...]] = ()
    references: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    async def run(self, ctx: ScanContext) -> list[Finding]:
        """Inspect the target via ``ctx`` and return zero or more findings."""

    def finding(
        self,
        *,
        title: str,
        description: str,
        remediation: str,
        location: Location,
        severity: Severity | None = None,
        confidence: Confidence = Confidence.HIGH,
        dedup_key: str = "",
        evidence: Sequence[EvidenceItem] = (),
    ) -> Finding:
        """Build a :class:`Finding` pre-filled from this check's class metadata."""
        return Finding(
            check_id=self.id,
            severity=severity if severity is not None else self.default_severity,
            confidence=confidence,
            title=title,
            description=description,
            location=location,
            remediation=remediation,
            evidence=tuple(evidence),
            cwe=tuple(self.cwe),
            references=tuple(self.references),
            fingerprint=compute_fingerprint(self.id, location, dedup_key),
        )
