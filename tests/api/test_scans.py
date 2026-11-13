"""
Scan routes: create, queue, lifecycle, cancel, delete, list, findings — RF-08..RF-17.

Drives the real app through ``TestClient``; ``auth_client`` is wired to a fake
orchestrator that completes instantly (``_wait_status`` polls until ``completed``).
The lifecycle tests that need a scan pinned in RUNNING build their own app with
:class:`BlockingOrchestrator`.
"""

from __future__ import annotations

import base64
import time

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from tests.api.conftest import ADMIN, BlockingOrchestrator, FakeOrchestrator
from tests.support import make_finding, make_result
from webvigil.api.app import create_app
from webvigil.api.config import WebConfig
from webvigil.api.db import Scan, ScanStatus
from webvigil.api.routes.scans import MAX_QUEUED_SCANS
from webvigil.core.findings import Severity


def _wait_status(client: TestClient, scan_id: int, target: str, timeout: float = 5.0) -> None:
    """
    Poll scan ``scan_id`` until its status is ``target``, or fail after ``timeout`` seconds.

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


def _completed_scan(client: TestClient) -> int:
    """
    Args:
        client (TestClient): An authenticated API client.

    Returns:
        int: The id of a new scan of ``FakeOrchestrator.result``, once it is ``completed``.
    """
    scan_id: int = client.post("/api/scans", json={"target": "https://example.com"}).json()["id"]
    _wait_status(client, scan_id, "completed")
    return scan_id


# ---------------------------------------------------------------------------
# Create and validate
# ---------------------------------------------------------------------------


def test_create_validates_the_target(auth_client: TestClient) -> None:
    """A non-HTTP(S) target is rejected at creation with a 422."""
    assert auth_client.post("/api/scans", json={"target": "ftp://nope"}).status_code == 422


@pytest.mark.parametrize(
    "extra",
    [
        {"max_pages": 10_001},
        {"delay_ms": 60_001},
        {"target": "https://example.com/" + "a" * 2048},
        {"authorized_by": "x" * 257},
        {"disabled_checks": [f"check.{n}" for n in range(201)]},
        {"disabled_checks": ["c" * 129]},
    ],
)
def test_create_refuses_options_over_their_ceiling(
    auth_client: TestClient, extra: dict[str, object]
) -> None:
    """Every option is bounded, so one request cannot ask for an endless crawl or a huge row."""
    body = {"target": "https://example.com/", **extra}
    assert auth_client.post("/api/scans", json=body).status_code == 422


def test_create_accepts_options_at_their_ceiling(auth_client: TestClient) -> None:
    """The ceilings themselves are allowed."""
    body = {"target": "https://example.com/", "max_pages": 10_000, "delay_ms": 60_000}
    assert auth_client.post("/api/scans", json=body).status_code == 201


def test_create_refuses_a_scan_when_the_queue_is_full(auth_client: TestClient) -> None:
    """With ``MAX_QUEUED_SCANS`` waiting, a new scan is a 429 and nothing is added."""
    engine = auth_client.app.state.engine  # type: ignore[attr-defined]  # app is typed as ASGIApp
    with Session(engine) as session:
        for _ in range(MAX_QUEUED_SCANS):
            session.add(Scan(target="https://example.com/", mode="passive", scope="host"))
        session.commit()

    refused = auth_client.post("/api/scans", json={"target": "https://example.com/"})
    assert refused.status_code == 429
    with Session(engine) as session:
        assert len(session.exec(select(Scan)).all()) == MAX_QUEUED_SCANS


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

    findings = auth_client.get(f"/api/scans/{scan_id}/findings").json()["items"]
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

    high = auth_client.get(f"/api/scans/{scan_id}/findings?severity=high").json()["items"]
    assert [f["check_id"] for f in high] == ["tls.https"]
    csp = auth_client.get(f"/api/scans/{scan_id}/findings?check_id=http.headers.csp").json()[
        "items"
    ]
    assert [f["check_id"] for f in csp] == ["http.headers.csp"]


def _all_pages(client: TestClient, path: str) -> list[dict[str, object]]:
    """
    Follow ``next_cursor`` from ``path`` to the last page.

    Args:
        client (TestClient): An authenticated API client.
        path (str): The findings URL, with its query string.

    Returns:
        list[dict[str, object]]: Every page's items, in order.
    """
    items: list[dict[str, object]] = []
    url = path
    while True:
        page = client.get(url).json()
        items.extend(page["items"])
        if page["next_cursor"] is None:
            return items
        url = f"{path}&cursor={page['next_cursor']}"


def test_findings_pages_follow_the_report_order(auth_client: TestClient) -> None:
    """Pages of findings concatenate, with no overlap, into the order the report sorts by."""
    findings = [
        make_finding(severity=Severity.LOW, url="https://example.com/b", dedup_key="1"),
        make_finding(check_id="injection.xss", severity=Severity.HIGH, param="q", dedup_key="2"),
        make_finding(severity=Severity.LOW, url="https://example.com/a", dedup_key="3"),
        make_finding(check_id="injection.xss", severity=Severity.HIGH, param="id", dedup_key="4"),
        make_finding(check_id="tls.https", severity=Severity.HIGH, header=None, dedup_key="5"),
        make_finding(check_id="disclosure.vcs", severity=Severity.CRITICAL, dedup_key="6"),
        make_finding(check_id="http.headers.hsts", dedup_key="7"),
    ]
    FakeOrchestrator.result = make_result(*findings)
    scan_id = _completed_scan(auth_client)
    expected = sorted(
        findings,
        key=lambda f: (
            -f.severity,
            f.check_id,
            f.location.url,
            f.location.param or f.location.header or f.location.cookie or "",
        ),
    )

    first = auth_client.get(f"/api/scans/{scan_id}/findings?limit=3").json()
    assert len(first["items"]) == 3
    assert first["total"] == 7
    pages = _all_pages(auth_client, f"/api/scans/{scan_id}/findings?limit=3")
    assert [f["fingerprint"] for f in pages] == [f.fingerprint for f in expected]


def test_findings_search_matches_title_url_and_location_names(auth_client: TestClient) -> None:
    """``q`` matches the title, URL, parameter or header name, ignoring case; so does ``total``."""
    FakeOrchestrator.result = make_result(
        make_finding(check_id="injection.xss", param="search", dedup_key="1"),
        make_finding(url="https://example.com/admin", dedup_key="2"),
        make_finding(check_id="tls.https", header="Strict-Transport-Security", dedup_key="3"),
    )
    scan_id = _completed_scan(auth_client)
    base = f"/api/scans/{scan_id}/findings"

    def checks(query: str) -> list[object]:
        page = auth_client.get(f"{base}?q={query}").json()
        assert page["total"] == len(page["items"])
        return [f["check_id"] for f in page["items"]]

    assert checks("XSS") == ["injection.xss"]
    assert checks("/ADMIN") == ["http.headers.csp"]
    assert checks("search") == ["injection.xss"]
    assert checks("transport") == ["tls.https"]
    assert len(checks("%20")) == 3  # a blank search matches everything


def test_findings_search_treats_wildcards_as_text(auth_client: TestClient) -> None:
    """``%`` and ``_`` in ``q`` match themselves, not any text (no ``LIKE`` wildcard)."""
    FakeOrchestrator.result = make_result(
        make_finding(param="user_id", dedup_key="1"),
        make_finding(param="userXid", dedup_key="2"),
    )
    scan_id = _completed_scan(auth_client)
    base = f"/api/scans/{scan_id}/findings"

    underscore = auth_client.get(f"{base}?q=user_id").json()["items"]
    assert [f["location"]["param"] for f in underscore] == ["user_id"]
    assert auth_client.get(f"{base}?q=%25").json()["total"] == 0


def test_finding_checks_count_each_check(auth_client: TestClient) -> None:
    """``/findings/checks`` lists only the checks with findings, with their count, by id."""
    FakeOrchestrator.result = make_result(
        make_finding(check_id="tls.https", dedup_key="1"),
        make_finding(check_id="http.headers.csp", dedup_key="2"),
        make_finding(check_id="http.headers.csp", url="https://example.com/a", dedup_key="3"),
    )
    scan_id = _completed_scan(auth_client)

    assert auth_client.get(f"/api/scans/{scan_id}/findings/checks").json() == [
        {"check_id": "http.headers.csp", "count": 2},
        {"check_id": "tls.https", "count": 1},
    ]


@pytest.mark.parametrize(
    "query",
    [
        "limit=0",
        "limit=201",
        "cursor=not*base64",
        f"cursor={base64.urlsafe_b64encode(b'-1').decode()}",
        f"cursor={base64.urlsafe_b64encode(b'x').decode()}",
        f"q={'a' * 201}",
        "severity=urgent",
    ],
)
def test_findings_refuse_a_bad_page_request(auth_client: TestClient, query: str) -> None:
    """A size outside 1..200, a bad cursor, an overlong search or an unknown severity is a 422."""
    FakeOrchestrator.result = make_result(make_finding())
    scan_id = _completed_scan(auth_client)
    assert auth_client.get(f"/api/scans/{scan_id}/findings?{query}").status_code == 422


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


@pytest.mark.parametrize("scan_id", ["99999999999999999999999", str(2**63), "0", "-1"])
def test_out_of_range_scan_id_is_422_on_every_route(auth_client: TestClient, scan_id: str) -> None:
    """
    An id no row can have is refused with a 422 before the database sees it (issue #160).

    Above 2**63 - 1 the SQLite driver raises OverflowError, which used to be a 500 with a
    traceback in the log. ``TestClient`` re-raises a server error, so the old behaviour fails here.
    """
    base = f"/api/scans/{scan_id}"
    assert auth_client.get(base).status_code == 422
    assert auth_client.get(f"{base}/findings").status_code == 422
    assert auth_client.get(f"{base}/findings/checks").status_code == 422
    assert auth_client.get(f"{base}/report?format=json").status_code == 422
    assert auth_client.post(f"{base}/cancel").status_code == 422
    assert auth_client.delete(base).status_code == 422


def test_largest_scan_id_is_still_a_404(auth_client: TestClient) -> None:
    """The top of the range is a valid id that names no scan: 404, not 422."""
    assert auth_client.get(f"/api/scans/{2**63 - 1}").status_code == 404


def test_cursor_with_an_out_of_range_id_is_a_422(auth_client: TestClient) -> None:
    """A cursor that carries an id outside the row range is an invalid cursor, not a 500."""
    raw = f"2026-01-01T00:00:00|{2**70}"
    cursor = base64.urlsafe_b64encode(raw.encode()).decode()
    response = auth_client.get("/api/scans", params={"cursor": cursor})
    assert response.status_code == 422
    assert response.json()["detail"] == "invalid cursor"


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
        assert client.get(f"/api/scans/{scan_id}/findings").json()["items"] == []
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
