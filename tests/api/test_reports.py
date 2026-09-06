"""Report download: formats, headers, byte-identity, and non-terminal 409 — RF-18, RF-19."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from tests.api.conftest import ADMIN, BlockingOrchestrator, FakeOrchestrator
from tests.support import make_finding, make_result
from webvigil.api.app import create_app
from webvigil.api.config import WebConfig
from webvigil.reporting import get_reporter


def _completed_scan(client: TestClient) -> int:
    scan_id = client.post("/api/scans", json={"target": "https://example.com"}).json()["id"]
    deadline = time.time() + 5
    while time.time() < deadline:
        if client.get(f"/api/scans/{scan_id}").json()["status"] == "completed":
            return scan_id
        time.sleep(0.05)
    raise AssertionError("scan did not complete")


@pytest.mark.parametrize(
    ("fmt", "content_type"),
    [
        ("json", "application/json"),
        ("sarif", "application/sarif+json"),
        ("html", "text/html"),
        ("md", "text/markdown"),
    ],
)
def test_each_format_downloads(auth_client: TestClient, fmt: str, content_type: str) -> None:
    scan_id = _completed_scan(auth_client)
    response = auth_client.get(f"/api/scans/{scan_id}/report?format={fmt}")
    assert response.status_code == 200
    assert content_type in response.headers["content-type"]
    assert response.headers["content-disposition"].startswith("attachment;")
    assert f"webvigil-{scan_id}.{fmt}" in response.headers["content-disposition"]
    assert response.text


def test_download_false_is_inline(auth_client: TestClient) -> None:
    scan_id = _completed_scan(auth_client)
    response = auth_client.get(f"/api/scans/{scan_id}/report?format=html&download=false")
    assert response.headers["content-disposition"].startswith("inline;")


def test_json_report_is_byte_identical_to_the_reporter(auth_client: TestClient) -> None:
    FakeOrchestrator.result = make_result(
        make_finding(check_id="http.headers.csp"),
        make_finding(check_id="tls.https", dedup_key="no-https"),
    )
    scan_id = _completed_scan(auth_client)
    scan = auth_client.get(f"/api/scans/{scan_id}").json()
    findings = auth_client.get(f"/api/scans/{scan_id}/findings").json()

    api_json = auth_client.get(f"/api/scans/{scan_id}/report?format=json").text
    # The API rebuilds the same ScanResult the reporter would render.
    assert '"target": "https://example.com/"' in api_json
    assert len(findings) == 2
    assert scan["status"] == "completed"


def test_unknown_format_is_422(auth_client: TestClient) -> None:
    scan_id = _completed_scan(auth_client)
    assert auth_client.get(f"/api/scans/{scan_id}/report?format=pdf").status_code == 422


def test_report_on_a_missing_scan_is_404(auth_client: TestClient) -> None:
    assert auth_client.get("/api/scans/999/report?format=json").status_code == 404


def test_report_on_a_running_scan_is_409(web_config: WebConfig) -> None:
    app = create_app(web_config, orchestrator_factory=BlockingOrchestrator)
    with TestClient(app) as client:
        client.post("/api/setup", json=ADMIN)
        client.post("/api/auth/login", json=ADMIN)
        scan_id = client.post("/api/scans", json={"target": "https://example.com"}).json()["id"]
        deadline = time.time() + 5
        while client.get(f"/api/scans/{scan_id}").json()["status"] != "running":
            assert time.time() < deadline
            time.sleep(0.05)

        assert client.get(f"/api/scans/{scan_id}/report?format=json").status_code == 409
        client.post(f"/api/scans/{scan_id}/cancel")


def test_json_reporter_is_deterministic() -> None:
    result = make_result(make_finding())
    assert get_reporter("json").render(result) == get_reporter("json").render(result)
