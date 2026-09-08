"""
Scan routes: create, queue, lifecycle, cancel, delete, list, findings — RF-08..RF-17.

Drives the real app through ``TestClient``; ``auth_client`` is wired to a fake
orchestrator that completes instantly (``_wait_status`` polls until ``completed``).
The lifecycle tests that need a scan pinned in RUNNING build their own app with
:class:`BlockingOrchestrator`.
"""

from __future__ import annotations

import time

from fastapi.testclient import TestClient
from sqlmodel import Session

from tests.api.conftest import ADMIN, BlockingOrchestrator, FakeOrchestrator
from tests.support import make_finding, make_result
from webvigil.api.app import create_app
from webvigil.api.config import WebConfig
from webvigil.api.db import Scan, ScanStatus
from webvigil.core.findings import Severity


def _wait_status(client: TestClient, scan_id: int, target: str, timeout: float = 5.0) -> None:
    """Poll scan ``scan_id`` until its status is ``target``, or fail after ``timeout`` seconds.

    Args:
        client (TestClient): An authenticated API client.
        scan_id (int): The scan id to poll.
        target (str): The status string to wait for.
        timeout (float): Seconds to wait before giving up.
    """
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = client.get(f"/api/scans/{scan_id}").json()["status"]
        if last == target:
            return
        time.sleep(0.05)
    raise AssertionError(f"scan {scan_id} is {last}, expected {target}")


# ---------------------------------------------------------------------------
# Create and validate
# ---------------------------------------------------------------------------


def test_create_validates_the_target(auth_client: TestClient) -> None:
    """A non-HTTP(S) target is rejected at creation with a 422."""
    assert auth_client.post("/api/scans", json={"target": "ftp://nope"}).status_code == 422


def test_create_active_requires_authorization(auth_client: TestClient) -> None:
    """An active-mode scan needs ``authorized_by``; with it, creation succeeds and records it."""
    bad = auth_client.post("/api/scans", json={"target": "https://example.com", "mode": "active"})
    assert bad.status_code == 422
    ok = auth_client.post(
        "/api/scans",
        json={"target": "https://example.com", "mode": "active", "authorized_by": "Jane / #1"},
    )
    assert ok.status_code == 201
    assert ok.json()["authorized_by"] == "Jane / #1"


# ---------------------------------------------------------------------------
# Lifecycle, findings, and the technology inventory
# ---------------------------------------------------------------------------


def test_scan_runs_to_completed_with_findings(auth_client: TestClient) -> None:
    """A created scan runs to ``completed`` and its findings are readable with their severity."""
    FakeOrchestrator.result = make_result(
        make_finding(check_id="http.headers.csp", severity=Severity.MEDIUM)
    )
    scan_id = auth_client.post("/api/scans", json={"target": "https://example.com"}).json()["id"]
    _wait_status(auth_client, scan_id, "completed")

    findings = auth_client.get(f"/api/scans/{scan_id}/findings").json()
    assert [f["check_id"] for f in findings] == ["http.headers.csp"]
    assert findings[0]["severity"] == "MEDIUM"


def test_scan_detail_exposes_the_technology_inventory(auth_client: TestClient) -> None:
    """The scan detail serialises the full technology inventory, advisories included."""
    from webvigil.core.technology import DetectionMethod, Technology

    FakeOrchestrator.result = make_result(
        make_finding(check_id="deps.js.vulnerable-library"),
        technologies=(
            Technology(
                name="jquery",
                version="1.7.1",
                detection=DetectionMethod.FILENAME,
                source_url="https://example.com/j.js",
                vulnerable=True,
                advisories=("CVE-2011-4969",),
            ),
        ),
    )
    scan_id = auth_client.post("/api/scans", json={"target": "https://example.com"}).json()["id"]
    _wait_status(auth_client, scan_id, "completed")

    detail = auth_client.get(f"/api/scans/{scan_id}").json()
    assert detail["technologies"] == [
        {
            "name": "jquery",
            "version": "1.7.1",
            "detection": "filename",
            "source_url": "https://example.com/j.js",
            "vulnerable": True,
            "advisories": ["CVE-2011-4969"],
        }
    ]


def test_scan_detail_technologies_default_to_empty(auth_client: TestClient) -> None:
    """A scan with no detected libraries reports an empty ``technologies`` list."""
    FakeOrchestrator.result = make_result(make_finding(check_id="http.headers.csp"))
    scan_id = auth_client.post("/api/scans", json={"target": "https://example.com"}).json()["id"]
    _wait_status(auth_client, scan_id, "completed")
    assert auth_client.get(f"/api/scans/{scan_id}").json()["technologies"] == []


def test_findings_filter_by_severity_and_check(auth_client: TestClient) -> None:
    """The findings endpoint filters by ``severity`` and by ``check_id``."""
    FakeOrchestrator.result = make_result(
        make_finding(check_id="tls.https", severity=Severity.HIGH, dedup_key="a"),
        make_finding(check_id="http.headers.csp", severity=Severity.LOW, dedup_key="b"),
    )
    scan_id = auth_client.post("/api/scans", json={"target": "https://example.com"}).json()["id"]
    _wait_status(auth_client, scan_id, "completed")

    high = auth_client.get(f"/api/scans/{scan_id}/findings?severity=high").json()
    assert [f["check_id"] for f in high] == ["tls.https"]
    csp = auth_client.get(f"/api/scans/{scan_id}/findings?check_id=http.headers.csp").json()
    assert [f["check_id"] for f in csp] == ["http.headers.csp"]


def test_list_pagination_and_status_filter(auth_client: TestClient) -> None:
    """The list endpoint paginates by cursor with no overlap and filters by status."""
    ids = [
        auth_client.post("/api/scans", json={"target": f"https://s{i}.example"}).json()["id"]
        for i in range(5)
    ]
    for scan_id in ids:
        _wait_status(auth_client, scan_id, "completed")

    first = auth_client.get("/api/scans?limit=2").json()
    assert len(first["items"]) == 2
    assert first["next_cursor"]
    second = auth_client.get(f"/api/scans?limit=2&cursor={first['next_cursor']}").json()
    assert len(second["items"]) == 2
    assert {i["id"] for i in first["items"]} & {i["id"] for i in second["items"]} == set()

    completed = auth_client.get("/api/scans?status=completed").json()
    assert len(completed["items"]) == 5


def test_delete_requires_a_terminal_scan(auth_client: TestClient) -> None:
    """A completed scan can be deleted and is then a 404."""
    scan_id = auth_client.post("/api/scans", json={"target": "https://example.com"}).json()["id"]
    _wait_status(auth_client, scan_id, "completed")
    assert auth_client.delete(f"/api/scans/{scan_id}").status_code == 204
    assert auth_client.get(f"/api/scans/{scan_id}").status_code == 404


def test_cancel_a_completed_scan_is_a_conflict(auth_client: TestClient) -> None:
    """Cancelling an already-completed scan is a 409."""
    scan_id = auth_client.post("/api/scans", json={"target": "https://example.com"}).json()["id"]
    _wait_status(auth_client, scan_id, "completed")
    assert auth_client.post(f"/api/scans/{scan_id}/cancel").status_code == 409


def test_missing_scan_is_404(auth_client: TestClient) -> None:
    """GET and DELETE on an unknown scan id are both 404."""
    assert auth_client.get("/api/scans/999").status_code == 404
    assert auth_client.delete("/api/scans/999").status_code == 404


def test_scan_routes_need_auth(client: TestClient) -> None:
    """The scan list and create routes are 401 without a session."""
    assert client.get("/api/scans").status_code == 401
    assert client.post("/api/scans", json={"target": "https://example.com"}).status_code == 401


# ---------------------------------------------------------------------------
# Running-scan lifecycle (BlockingOrchestrator)
# ---------------------------------------------------------------------------


def test_cancel_a_running_scan(web_config: WebConfig) -> None:
    """A RUNNING scan can be cancelled, ends CANCELLED with no findings, and is then deletable."""
    app = create_app(web_config, orchestrator_factory=BlockingOrchestrator)
    with TestClient(app) as client:
        client.post("/api/setup", json=ADMIN)
        client.post("/api/auth/login", json=ADMIN)
        scan_id = client.post("/api/scans", json={"target": "https://example.com"}).json()["id"]
        _wait_status(client, scan_id, "running")

        assert client.post(f"/api/scans/{scan_id}/cancel").status_code == 204
        _wait_status(client, scan_id, "cancelled")
        assert client.get(f"/api/scans/{scan_id}/findings").json() == []
        assert client.delete(f"/api/scans/{scan_id}").status_code == 204


def test_deleting_a_running_scan_is_a_conflict(web_config: WebConfig) -> None:
    """Deleting a RUNNING scan is a 409."""
    app = create_app(web_config, orchestrator_factory=BlockingOrchestrator)
    with TestClient(app) as client:
        client.post("/api/setup", json=ADMIN)
        client.post("/api/auth/login", json=ADMIN)
        scan_id = client.post("/api/scans", json={"target": "https://example.com"}).json()["id"]
        _wait_status(client, scan_id, "running")
        assert client.delete(f"/api/scans/{scan_id}").status_code == 409
        client.post(f"/api/scans/{scan_id}/cancel")


def test_restart_marks_stuck_running_scans_interrupted(
    web_config: WebConfig, web_engine: object
) -> None:
    """On app startup a scan left RUNNING from a previous process shows as ``interrupted``."""
    with Session(web_engine) as session:  # type: ignore[arg-type]
        session.add(
            Scan(target="https://x.test/", mode="passive", scope="host", status=ScanStatus.RUNNING)
        )
        session.commit()

    app = create_app(web_config, orchestrator_factory=FakeOrchestrator)
    with TestClient(app) as client:
        client.post("/api/setup", json=ADMIN)
        client.post("/api/auth/login", json=ADMIN)
        items = client.get("/api/scans").json()["items"]
        assert items[0]["status"] == "interrupted"
