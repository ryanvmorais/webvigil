"""Conversions between the engine models, the DB rows, and a rebuilt ``ScanResult``."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlmodel import Session

from webvigil.api.db import Finding as FindingRow
from webvigil.api.db import Scan, ScanStatus, utcnow
from webvigil.core import (
    CheckError,
    Confidence,
    EvidenceItem,
    Finding,
    Location,
    ScanConfig,
    ScanMetadata,
    ScanMode,
    ScanResult,
    Scope,
    Severity,
)


def build_scan_config(scan: Scan) -> ScanConfig:
    """Turn a stored ``Scan`` into the ``ScanConfig`` the engine expects."""
    options = scan.options or {}
    scan_overrides: dict[str, object] = {"mode": scan.mode, "scope": scan.scope}
    for key in ("max_pages", "follow_robots"):
        if key in options:
            scan_overrides[key] = options[key]
    http_overrides: dict[str, object] = {}
    if "delay_ms" in options:
        http_overrides["delay_ms"] = options["delay_ms"]
    checks_overrides: dict[str, object] = {}
    if options.get("disabled_checks"):
        checks_overrides["disabled"] = options["disabled_checks"]

    overrides: dict[str, dict[str, object]] = {
        "scan": scan_overrides,
        "http": http_overrides,
        "checks": checks_overrides,
    }
    if scan.mode == ScanMode.ACTIVE.value:
        overrides["active"] = {"authorized_by": scan.authorized_by or ""}
    return ScanConfig().with_overrides(**overrides)


def store_result(session: Session, scan_id: int, result: ScanResult) -> None:
    """Persist a completed scan: metadata onto the row, one ``finding`` row per finding."""
    scan = session.get(Scan, scan_id)
    if scan is None:  # pragma: no cover - the runner always has a row
        raise LookupError(f"scan {scan_id} disappeared")
    meta = result.metadata
    scan.status = ScanStatus.COMPLETED
    scan.tool_version = meta.tool_version
    scan.started_at = meta.started_at
    scan.finished_at = meta.finished_at
    scan.pages_scanned = meta.pages_scanned
    scan.counts = dict(meta.counts)
    scan.check_errors = [error.model_dump() for error in result.errors]
    scan.warnings = list(result.warnings)
    scan.error = None
    session.add(scan)
    for finding in result.findings:
        session.add(
            FindingRow(
                scan_id=scan_id,
                check_id=finding.check_id,
                severity=int(finding.severity),
                confidence=int(finding.confidence),
                title=finding.title,
                description=finding.description,
                location=finding.location.model_dump(),
                remediation=finding.remediation,
                evidence=[item.model_dump() for item in finding.evidence],
                cwe=list(finding.cwe),
                references=list(finding.references),
                fingerprint=finding.fingerprint,
            )
        )
    session.commit()


def rows_to_result(scan: Scan, findings: list[FindingRow]) -> ScanResult:
    """Rebuild the engine's ``ScanResult`` from stored rows, for the reporters (RF-19)."""
    metadata = ScanMetadata(
        target=scan.target,
        mode=ScanMode(scan.mode),
        scope=Scope(scan.scope),
        authorized_by=scan.authorized_by,
        tool_version=scan.tool_version or "",
        started_at=_as_utc(scan.started_at),
        finished_at=_as_utc(scan.finished_at),
        pages_scanned=scan.pages_scanned,
        counts=dict(scan.counts),
    )
    return ScanResult(
        metadata=metadata,
        findings=tuple(_row_to_finding(row) for row in findings),
        errors=tuple(CheckError(**error) for error in scan.check_errors),
        warnings=tuple(scan.warnings),
    )


def _row_to_finding(row: FindingRow) -> Finding:
    return Finding(
        check_id=row.check_id,
        severity=Severity(row.severity),
        confidence=Confidence(row.confidence),
        title=row.title,
        description=row.description,
        location=Location(**row.location),
        remediation=row.remediation,
        evidence=tuple(EvidenceItem(**item) for item in row.evidence),
        cwe=tuple(row.cwe),
        references=tuple(row.references),
        fingerprint=row.fingerprint,
    )


def _as_utc(value: datetime | None) -> datetime:
    """SQLite hands back naive datetimes; the engine wrote them in UTC."""
    if value is None:
        return utcnow()
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
