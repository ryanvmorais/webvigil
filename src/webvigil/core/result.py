"""The result of a scan: metadata, findings, per-check errors, and warnings.

Serialized to JSON this is the canonical report format (RF-21); every other reporter is a
pure function of a ``ScanResult`` and ``webvigil report`` reloads one from disk.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from webvigil.core.findings import Finding, ScanMode, Severity
from webvigil.core.target import Scope
from webvigil.core.technology import Technology


class ScanMetadata(BaseModel):
    """Everything about a scan except the findings themselves."""

    model_config = ConfigDict(frozen=True)

    target: str
    mode: ScanMode
    scope: Scope
    tool_version: str
    started_at: datetime
    finished_at: datetime
    pages_scanned: int
    counts: dict[str, int]
    authorized_by: str | None = None


class CheckError(BaseModel):
    """A check that raised instead of returning findings."""

    model_config = ConfigDict(frozen=True)

    check_id: str
    message: str
    traceback: str


class ScanResult(BaseModel):
    """The complete outcome of one scan."""

    model_config = ConfigDict(frozen=True)

    metadata: ScanMetadata
    findings: tuple[Finding, ...]
    technologies: tuple[Technology, ...] = ()
    errors: tuple[CheckError, ...] = ()
    warnings: tuple[str, ...] = ()

    @staticmethod
    def severity_counts(findings: tuple[Finding, ...]) -> dict[str, int]:
        """Count findings per severity name, including zero buckets, for report headers."""
        counts = {level.name: 0 for level in Severity}
        for finding in findings:
            counts[finding.severity.name] += 1
        return counts
