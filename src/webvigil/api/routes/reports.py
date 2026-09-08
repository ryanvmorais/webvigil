"""
Report download for a finished scan (RF-18).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Response, status
from sqlmodel import select

from webvigil.api.db import Finding as FindingRow
from webvigil.api.db import Scan, ScanStatus
from webvigil.api.deps import CurrentUser, SessionDep
from webvigil.api.mapping import rows_to_result
from webvigil.reporting import get_reporter

router = APIRouter(prefix="/scans", tags=["reports"])

_FORMATS = ("json", "sarif", "html", "md")
_WITH_RESULTS = {ScanStatus.COMPLETED, ScanStatus.INTERRUPTED}
_MEDIA_TYPE = {
    "json": "application/json",
    "sarif": "application/sarif+json",
    "html": "text/html; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
}


@router.get("/{scan_id}/report")
def download_report(
    scan_id: int,
    _user: CurrentUser,
    session: SessionDep,
    report_format: str = Query(default="json", alias="format"),
    download: bool = Query(default=True),
) -> Response:
    """Render a finished scan into ``json`` / ``sarif`` / ``html`` / ``md`` from the stored
    rows. ``download=false`` serves it inline. 409 when the scan has no results."""
    if report_format not in _FORMATS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown format: {report_format!r}"
        )
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    if ScanStatus(scan.status) not in _WITH_RESULTS:
        raise HTTPException(status.HTTP_409_CONFLICT, "the scan has no results to report")

    findings = list(session.exec(select(FindingRow).where(FindingRow.scan_id == scan_id)))
    body = get_reporter(report_format).render(rows_to_result(scan, findings))
    disposition = "attachment" if download else "inline"
    return Response(
        content=body,
        media_type=_MEDIA_TYPE[report_format],
        headers={
            "content-disposition": (f'{disposition}; filename="webvigil-{scan_id}.{report_format}"')
        },
    )
