"""Scan CRUD, the queue, and findings (RF-08..RF-17)."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import and_, or_
from sqlmodel import col, select

from webvigil.api.db import TERMINAL_STATUSES, Scan, ScanStatus
from webvigil.api.db import Finding as FindingRow
from webvigil.api.deps import CurrentUser, RunnerDep, SessionDep
from webvigil.api.schemas import FindingOut, Page, ScanCreate, ScanOut, ScanSummary
from webvigil.core.findings import Severity
from webvigil.core.target import Target

router = APIRouter(prefix="/scans", tags=["scans"])

_LIST_LIMIT_DEFAULT = 20
_LIST_LIMIT_MAX = 100


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: ScanCreate, _user: CurrentUser, session: SessionDep, runner: RunnerDep
) -> ScanOut:
    scan = Scan(
        target=Target.parse(body.target).entry_url,
        mode=body.mode.value,
        scope=body.scope.value,
        authorized_by=body.authorized_by.strip() if body.authorized_by else None,
        options=body.to_options(),
        status=ScanStatus.QUEUED,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    runner.wake()
    return ScanOut.from_row(scan)


@router.get("")
def list_scans(
    _user: CurrentUser,
    session: SessionDep,
    scan_status: ScanStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=_LIST_LIMIT_DEFAULT, ge=1, le=_LIST_LIMIT_MAX),
    cursor: str | None = None,
) -> Page[ScanSummary]:
    statement = select(Scan).order_by(col(Scan.created_at).desc(), col(Scan.id).desc())
    if scan_status is not None:
        statement = statement.where(Scan.status == scan_status)
    if cursor is not None:
        created_at, scan_id = _decode_cursor(cursor)
        statement = statement.where(
            or_(
                col(Scan.created_at) < created_at,
                and_(col(Scan.created_at) == created_at, col(Scan.id) < scan_id),
            )
        )
    rows = list(session.exec(statement.limit(limit + 1)))
    next_cursor: str | None = None
    if len(rows) > limit:
        rows = rows[:limit]
        next_cursor = _encode_cursor(rows[-1])
    return Page(items=[ScanSummary.from_row(row) for row in rows], next_cursor=next_cursor)


@router.get("/{scan_id}")
def get_scan(scan_id: int, _user: CurrentUser, session: SessionDep) -> ScanOut:
    return ScanOut.from_row(_load(session, scan_id))


@router.get("/{scan_id}/findings")
def list_findings(
    scan_id: int,
    _user: CurrentUser,
    session: SessionDep,
    severity: str | None = None,
    check_id: str | None = None,
) -> list[FindingOut]:
    _load(session, scan_id)
    statement = select(FindingRow).where(FindingRow.scan_id == scan_id)
    if check_id is not None:
        statement = statement.where(FindingRow.check_id == check_id)
    rows = list(session.exec(statement))
    if severity is not None:
        try:
            threshold = int(Severity.from_name(severity))
        except KeyError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unknown severity") from exc
        rows = [row for row in rows if row.severity >= threshold]
    rows.sort(
        key=lambda row: (
            -row.severity,
            row.check_id,
            str(row.location.get("url", "")),
            _location_key(row.location),
        )
    )
    return [FindingOut.from_row(row) for row in rows]


@router.post("/{scan_id}/cancel", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_scan(
    scan_id: int, _user: CurrentUser, session: SessionDep, runner: RunnerDep
) -> None:
    scan = _load(session, scan_id)
    if ScanStatus(scan.status) in TERMINAL_STATUSES:
        raise HTTPException(status.HTTP_409_CONFLICT, "scan is already finished")
    if await runner.cancel(scan_id) == "not_cancellable":
        raise HTTPException(status.HTTP_409_CONFLICT, "scan could not be cancelled")


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: int, _user: CurrentUser, session: SessionDep) -> None:
    scan = _load(session, scan_id)
    if ScanStatus(scan.status) not in TERMINAL_STATUSES:
        raise HTTPException(status.HTTP_409_CONFLICT, "cancel the scan before deleting it")
    session.delete(scan)
    session.commit()


def _load(session: SessionDep, scan_id: int) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return scan


def _location_key(location: dict[str, object]) -> str:
    for key in ("param", "header", "cookie"):
        value = location.get(key)
        if value:
            return str(value)
    return ""


def _encode_cursor(scan: Scan) -> str:
    raw = f"{scan.created_at.isoformat()}|{scan.id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, int]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        created_at, scan_id = raw.rsplit("|", 1)
        return datetime.fromisoformat(created_at), int(scan_id)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid cursor") from exc
