"""
Report download for a finished scan (RF-18).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Response, status
from sqlmodel import select

from webvigil.api.db import Finding as FindingRow
from webvigil.api.db import Scan, ScanStatus
from webvigil.api.deps import CurrentUser, ScanId, SessionDep
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
# A report is built from what the scanned site sent, and the HTML one is served inline from the
# API's own origin. The template escapes it, so nothing is known to be wrong; these two headers are
# what would contain a mistake (issue #163). ``nosniff`` keeps a browser from reading any report as
# another type. The policy gives the HTML page a unique origin with no script, form or fetch, and
# leaves it the one thing it uses: its inline ``<style>``. The dashboard's preview does not depend
# on it (it renders a ``blob:`` in a sandboxed iframe); a report opened inline in a tab does.
_HTML_CSP = "sandbox; default-src 'none'; style-src 'unsafe-inline'"


@router.get("/{scan_id}/report")
def download_report(
    scan_id: ScanId,
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
    headers = {
        "content-disposition": f'{disposition}; filename="webvigil-{scan_id}.{report_format}"',
        "x-content-type-options": "nosniff",
    }
    if report_format == "html":
        headers["content-security-policy"] = _HTML_CSP
    return Response(content=body, media_type=_MEDIA_TYPE[report_format], headers=headers)
