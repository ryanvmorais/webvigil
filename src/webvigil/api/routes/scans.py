"""Scan CRUD, the queue, and findings (RF-08..RF-17)."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import ColumnElement, and_, func, or_
from sqlmodel import col, select

from webvigil.api.db import TERMINAL_STATUSES, Scan, ScanStatus
from webvigil.api.db import Finding as FindingRow
from webvigil.api.deps import MAX_ROW_ID, CurrentUser, RunnerDep, ScanId, SessionDep
from webvigil.api.schemas import (
    CheckCount,
    FindingOut,
    FindingPage,
    Page,
    ScanCreate,
    ScanOut,
    ScanSummary,
)
from webvigil.core.findings import Severity
from webvigil.core.target import Target

router = APIRouter(prefix="/scans", tags=["scans"])

_LIST_LIMIT_DEFAULT = 20
_LIST_LIMIT_MAX = 100
# Scans waiting at once. One runs at a time, so a longer queue is hours of work nobody is watching;
# the cap keeps a script stuck in a loop from filling the database with queued rows.
MAX_QUEUED_SCANS = 100
# A page of findings the dashboard draws at once. A hostile site can make a scan produce thousands
# of findings; the whole set is in the JSON report, not in one response.
_FINDINGS_LIMIT_DEFAULT = 50
_FINDINGS_LIMIT_MAX = 200
# Longer than any URL fragment or title a person types; the cap keeps the LIKE pattern small.
_SEARCH_MAX_LENGTH = 200
_SUB_KEYS = ("param", "header", "cookie")


def _location_field(key: str) -> ColumnElement[Any]:
    """
    Args:
        key (str): A :class:`~webvigil.core.findings.Location` field.

    Returns:
        ColumnElement[Any]: That field read from the stored location JSON (SQLite
            ``json_extract``); ``NULL`` when it is absent.
    """
    return func.json_extract(col(FindingRow.location), f"$.{key}")


_URL = func.coalesce(_location_field("url"), "")
# The first non-empty of param / header / cookie, as the report sorts by.
_SUB_LOCATION = func.coalesce(*(func.nullif(_location_field(key), "") for key in _SUB_KEYS), "")
# Severity first, then check id / URL / sub-location; the id breaks ties so pages never overlap.
_FINDING_ORDER = (
    col(FindingRow.severity).desc(),
    col(FindingRow.check_id),
    _URL,
    _SUB_LOCATION,
    col(FindingRow.id),
)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: ScanCreate, _user: CurrentUser, session: SessionDep, runner: RunnerDep
) -> ScanOut:
    """
    Queue a scan and wake the runner. Returns the new scan row (status ``queued``).

    429 when ``MAX_QUEUED_SCANS`` are already waiting.
    """
    queued = session.exec(
        select(func.count()).select_from(Scan).where(Scan.status == ScanStatus.QUEUED)
    ).one()
    if queued >= MAX_QUEUED_SCANS:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"{MAX_QUEUED_SCANS} scans are already queued: wait for some to finish",
        )
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
    """Newest scans first, optionally filtered by ``status``, cursor-paginated by ``limit``."""
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
def get_scan(scan_id: ScanId, _user: CurrentUser, session: SessionDep) -> ScanOut:
    """One scan's full detail — metadata, options, and the detected-technology inventory."""
    return ScanOut.from_row(_load(session, scan_id))


@router.get("/{scan_id}/findings")
def list_findings(
    scan_id: ScanId,
    _user: CurrentUser,
    session: SessionDep,
    severity: str | None = None,
    check_id: str | None = None,
    q: str | None = Query(default=None, max_length=_SEARCH_MAX_LENGTH),
    limit: int = Query(default=_FINDINGS_LIMIT_DEFAULT, ge=1, le=_FINDINGS_LIMIT_MAX),
    cursor: str | None = None,
) -> FindingPage:
    """
    A page of a scan's findings, sorted severity-descending then check id / URL / sub-location.

    Optionally filtered by ``check_id``, a minimum ``severity``, and ``q``: a case-insensitive
    substring of the title, the URL, or the parameter, header or cookie name. ``total`` counts
    every match. The findings are written once, when the scan completes, so an offset cursor
    is stable between pages.
    """
    _load(session, scan_id)
    conditions = _finding_conditions(scan_id, severity, check_id, q)
    total = session.exec(select(func.count()).select_from(FindingRow).where(*conditions)).one()
    offset = _decode_offset(cursor) if cursor is not None else 0
    statement = (
        select(FindingRow)
        .where(*conditions)
        .order_by(*_FINDING_ORDER)
        .offset(offset)
        .limit(limit + 1)
    )
    rows = list(session.exec(statement))
    next_cursor: str | None = None
    if len(rows) > limit:
        rows = rows[:limit]
        next_cursor = _encode_offset(offset + limit)
    return FindingPage(
        items=[FindingOut.from_row(row) for row in rows], next_cursor=next_cursor, total=total
    )


@router.get("/{scan_id}/findings/checks")
def list_finding_checks(
    scan_id: ScanId, _user: CurrentUser, session: SessionDep
) -> list[CheckCount]:
    """The checks that found something in a scan, each with its number of findings, by check id."""
    _load(session, scan_id)
    statement = (
        select(FindingRow.check_id, func.count())
        .where(FindingRow.scan_id == scan_id)
        .group_by(col(FindingRow.check_id))
        .order_by(col(FindingRow.check_id))
    )
    return [CheckCount(check_id=check, count=count) for check, count in session.exec(statement)]


@router.post("/{scan_id}/cancel", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_scan(
    scan_id: ScanId, _user: CurrentUser, session: SessionDep, runner: RunnerDep
) -> None:
    """Cancel a running or queued scan. 409 if it is already finished or not cancellable."""
    scan = _load(session, scan_id)
    if ScanStatus(scan.status) in TERMINAL_STATUSES:
        raise HTTPException(status.HTTP_409_CONFLICT, "scan is already finished")
    if await runner.cancel(scan_id) == "not_cancellable":
        raise HTTPException(status.HTTP_409_CONFLICT, "scan could not be cancelled")


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: ScanId, _user: CurrentUser, session: SessionDep) -> None:
    """Delete a finished scan and its findings (cascade). 409 if it is still active."""
    scan = _load(session, scan_id)
    if ScanStatus(scan.status) not in TERMINAL_STATUSES:
        raise HTTPException(status.HTTP_409_CONFLICT, "cancel the scan before deleting it")
    session.delete(scan)
    session.commit()


def _load(session: SessionDep, scan_id: int) -> Scan:
    """
    Args:
        session (SessionDep): The request-scoped session.
        scan_id (int): The scan to load.

    Returns:
        Scan: The scan row.

    Raises:
        HTTPException: 404 when there is no such scan.
    """
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return scan


def _finding_conditions(
    scan_id: int, severity: str | None, check_id: str | None, q: str | None
) -> list[ColumnElement[bool]]:
    """
    Args:
        scan_id (int): The scan whose findings are listed.
        severity (str | None): A minimum severity name, or ``None``.
        check_id (str | None): One check id, or ``None``.
        q (str | None): Search text, or ``None``; blank text matches everything.

    Returns:
        list[ColumnElement[bool]]: The ``WHERE`` conditions, joined by ``AND``.

    Raises:
        HTTPException: 422 when ``severity`` is not a severity name.
    """
    conditions: list[ColumnElement[bool]] = [col(FindingRow.scan_id) == scan_id]
    if check_id is not None:
        conditions.append(col(FindingRow.check_id) == check_id)
    if severity is not None:
        try:
            threshold = int(Severity.from_name(severity))
        except KeyError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unknown severity") from exc
        conditions.append(col(FindingRow.severity) >= threshold)
    if q is not None and q.strip():
        pattern = f"%{_escape_like(q.strip())}%"
        searched = (col(FindingRow.title), _URL, *(_location_field(key) for key in _SUB_KEYS))
        conditions.append(or_(*(field.ilike(pattern, escape="\\") for field in searched)))
    return conditions


def _escape_like(text: str) -> str:
    """
    Args:
        text (str): Search text as typed.

    Returns:
        str: The text with the backslash, ``%`` and ``_`` escaped, so they match themselves
            in a ``LIKE`` pattern (backslash as the escape) instead of acting as wildcards.
    """
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _encode_offset(offset: int) -> str:
    """
    Args:
        offset (int): How many findings the next page skips.

    Returns:
        str: An opaque, URL-safe cursor.
    """
    return base64.urlsafe_b64encode(str(offset).encode()).decode()


def _decode_offset(cursor: str) -> int:
    """
    Args:
        cursor (str): A cursor from :func:`_encode_offset`.

    Returns:
        int: The offset to page from.

    Raises:
        HTTPException: 422 when the cursor is malformed.
    """
    try:
        offset = int(base64.urlsafe_b64decode(cursor.encode()).decode())
        if not 0 <= offset <= MAX_ROW_ID:
            raise ValueError("cursor offset out of range")
        return offset
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid cursor") from exc


def _encode_cursor(scan: Scan) -> str:
    """
    Args:
        scan (Scan): The last row of a page.

    Returns:
        str: An opaque, URL-safe cursor encoding its ``created_at`` and ``id``.
    """
    raw = f"{scan.created_at.isoformat()}|{scan.id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, int]:
    """
    Args:
        cursor (str): A cursor from :func:`_encode_cursor`.

    Returns:
        tuple[datetime, int]: The ``created_at`` and ``id`` to page after.

    Raises:
        HTTPException: 422 when the cursor is malformed.
    """
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        created_at, scan_id = raw.rsplit("|", 1)
        position = int(scan_id)
        if not 1 <= position <= MAX_ROW_ID:
            raise ValueError("cursor id out of range")
        return datetime.fromisoformat(created_at), position
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid cursor") from exc
