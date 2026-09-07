"""
The check plugin contract (RF-08).

A check subclasses :class:`Check`, sets its class-level metadata, and implements
``async run(ctx) -> list[Finding]``. Use :meth:`Check.finding` to build findings
so the ``check_id``, CWE list, references, and fingerprint are filled in
consistently.
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
    """
    Base class for all checks.

    Attributes:
        id (ClassVar[str]): Stable, dotted check identifier (e.g.
            ``"http.headers.csp"``).
        name (ClassVar[str]): Human-readable one-line name.
        category (ClassVar[Category]): The broad group the check belongs to.
        mode (ClassVar[ScanMode]): Minimum scan mode the check runs in.
            Defaults to :attr:`~webvigil.core.findings.ScanMode.PASSIVE`.
        default_severity (ClassVar[Severity]): Severity used for a finding when
            :meth:`finding` is not given one.
        cwe (ClassVar[tuple[int, ...]]): CWE ids stamped on every finding.
            Defaults to empty.
        references (ClassVar[tuple[str, ...]]): Further-reading URLs stamped on
            every finding. Defaults to empty.
    """

    id: ClassVar[str]
    name: ClassVar[str]
    category: ClassVar[Category]
    mode: ClassVar[ScanMode] = ScanMode.PASSIVE
    default_severity: ClassVar[Severity]
    cwe: ClassVar[tuple[int, ...]] = ()
    references: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Inspect the target via ``ctx`` and return zero or more findings.

        Args:
            ctx (ScanContext): The shared, read-only scan context — config,
                target, HTTP client, discovered pages, forms, observations.

        Returns:
            list[Finding]: The findings this check produced, possibly empty.
        """

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
        """
        Build a :class:`Finding` pre-filled from this check's class metadata.

        The ``check_id``, ``cwe``, and ``references`` come from the class; the
        ``fingerprint`` is derived from ``id``, ``location``, and ``dedup_key``.

        Args:
            title (str): One-line summary of the issue.
            description (str): Full explanation.
            remediation (str): How to fix it.
            location (Location): Where the issue was observed.
            severity (Severity | None): Overrides ``default_severity`` when
                given.
            confidence (Confidence): How sure the check is. Defaults to
                :attr:`~webvigil.core.findings.Confidence.HIGH`.
            dedup_key (str): Extra string that distinguishes otherwise identical
                findings at the same location. Defaults to ``""``.
            evidence (Sequence[EvidenceItem]): Labelled snippets backing the
                finding. Defaults to empty.

        Returns:
            Finding: The assembled, frozen finding.
        """
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
