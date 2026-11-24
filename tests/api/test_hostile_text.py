"""
The Web API stores and serves what a scanned site sent, whatever its characters and size.

Drives the real app through ``TestClient`` with a fake orchestrator (no network). A result is
stored through the runner; a row an older version wrote is inserted directly, because a JSON
column could hold a character that UTF-8 cannot encode and only a read would then fail.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any

import httpx2
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlmodel import Session

from tests.api.conftest import ADMIN, FakeOrchestrator
from tests.http_mock import HttpxMock
from tests.support import make_finding, make_result
from webvigil.api.app import create_app
from webvigil.api.config import WebConfig
from webvigil.api.db import Finding as FindingRow
from webvigil.api.db import Scan, ScanStatus
from webvigil.api.runner import ScanRunner
from webvigil.core import InvalidTargetError, Orchestrator, ScanConfig, ScanResult
from webvigil.core.findings import Finding

_LONE = "\ud800"
_REPLACED = "�"
_FORMATS = ("json", "sarif", "html", "md")


def _wait_until(client: TestClient, scan_id: int, status: str) -> dict[str, object]:
    """
    Args:
        client (TestClient): An authenticated API client.
        scan_id (int): The scan to watch.
        status (str): The status to wait for.

    Returns:
        dict[str, object]: The scan's detail response, once it has that status.
    """
    deadline = time.time() + 5
    while time.time() < deadline:
        scan: dict[str, object] = client.get(f"/api/scans/{scan_id}").json()
        if scan["status"] == status:
            return scan
        time.sleep(0.02)
    raise AssertionError(f"scan {scan_id} did not reach {status}")


def _hostile_result() -> ScanResult:
    """
    Returns:
        ScanResult: A result built from text holding an unpaired surrogate.
    """
    finding = make_finding(url=f"https://example.com/{_LONE}", param=f"q{_LONE}")
    data = finding.model_dump()
    data["title"] = f"title{_LONE}"
    data["evidence"] = [{"label": "label", "content": f"evidence{_LONE}"}]
    return make_result(Finding.model_validate(data), warnings=[f"warning{_LONE}"])


@pytest.mark.parametrize("fmt", _FORMATS)
def test_a_scan_that_met_the_character_is_stored_and_served(
    auth_client: TestClient, fmt: str
) -> None:
    """The scan completes, and its findings and every report format come back."""
    FakeOrchestrator.result = _hostile_result()
    scan_id = auth_client.post("/api/scans", json={"target": "https://example.com"}).json()["id"]

    _wait_until(auth_client, scan_id, "completed")

    finding = auth_client.get(f"/api/scans/{scan_id}/findings").json()["items"][0]
    assert finding["location"]["url"] == f"https://example.com/{_REPLACED}"
    assert finding["evidence"][0]["content"] == f"evidence{_REPLACED}"
    report = auth_client.get(f"/api/scans/{scan_id}/report?format={fmt}")
    assert report.status_code == 200
    assert "title" + _REPLACED in report.text or "title\\ufffd" in report.text


@pytest.mark.parametrize("fmt", _FORMATS)
def test_a_row_an_older_version_stored_is_still_served(
    auth_client: TestClient, web_engine: Engine, fmt: str
) -> None:
    """JSON columns holding the character read back through every endpoint."""
    with Session(web_engine) as session:
        scan = Scan(
            target="https://example.com",
            mode="passive",
            scope="host",
            status=ScanStatus.COMPLETED,
            tool_version="0.0.0",
            counts={"MEDIUM": 1},
            warnings=[f"warning{_LONE}"],
            check_errors=[{"check_id": "c", "message": f"m{_LONE}", "traceback": "t"}],
            technologies=[
                {
                    "name": f"lib{_LONE}",
                    "version": f"1{_LONE}",
                    "detection": "uri",
                    "source_url": f"https://example.com/{_LONE}",
                    "vulnerable": True,
                    "advisories": [f"A{_LONE}"],
                }
            ],
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id
        assert scan_id is not None
        session.add(
            FindingRow(
                scan_id=scan_id,
                check_id="http.headers.csp",
                severity=20,
                confidence=30,
                title="title",
                description="description",
                location={
                    "url": f"https://example.com/{_LONE}",
                    "method": f"G{_LONE}",
                    "param": f"q{_LONE}",
                    "header": f"h{_LONE}",
                    "cookie": f"c{_LONE}",
                },
                remediation="remediation",
                evidence=[{"label": f"l{_LONE}", "content": f"e{_LONE}"}],
                cwe=[693],
                references=[f"https://example.com/r{_LONE}"],
                fingerprint="f" * 16,
            )
        )
        session.commit()
    # the row really holds the character the response could not encode
    with Session(web_engine) as session:
        stored = session.get(Scan, scan_id)
        assert stored is not None and stored.warnings == [f"warning{_LONE}"]

    detail = auth_client.get(f"/api/scans/{scan_id}")
    findings = auth_client.get(f"/api/scans/{scan_id}/findings")
    report = auth_client.get(f"/api/scans/{scan_id}/report?format={fmt}")

    assert detail.status_code == findings.status_code == report.status_code == 200
    technology = detail.json()["technologies"][0]
    assert (technology["name"], technology["version"]) == (f"lib{_REPLACED}", f"1{_REPLACED}")
    assert technology["source_url"] == f"https://example.com/{_REPLACED}"
    assert technology["advisories"] == [f"A{_REPLACED}"]
    item = findings.json()["items"][0]
    assert item["location"] == {
        "url": f"https://example.com/{_REPLACED}",
        "method": f"G{_REPLACED}",
        "param": f"q{_REPLACED}",
        "header": f"h{_REPLACED}",
        "cookie": f"c{_REPLACED}",
    }
    assert item["evidence"] == [{"label": f"l{_REPLACED}", "content": f"e{_REPLACED}"}]
    assert item["references"] == [f"https://example.com/r{_REPLACED}"]


class _FailingOrchestrator:
    """Fails every scan with the message the test sets."""

    message = ""

    def __init__(self, _config: ScanConfig) -> None: ...

    async def run(self, raw_target: str) -> ScanResult:
        raise InvalidTargetError(type(self).message)


@pytest.mark.parametrize(
    ("message", "stored"),
    [
        ("x" * 20_000, "x" * 16 * 1024 + "...[truncated]"),
        (f"bad{_LONE}name", f"bad{_REPLACED}name"),
        ("short failure", "short failure"),
    ],
    ids=["long", "unencodable", "control"],
)
def test_the_error_of_a_failed_scan_is_stored_bounded_and_encodable(
    web_config: WebConfig, web_engine: Engine, message: str, stored: str
) -> None:
    """A failure message that quotes the site is cut and cleaned, and the scan still ends."""
    _FailingOrchestrator.message = message
    app = create_app(web_config, orchestrator_factory=_FailingOrchestrator)
    with TestClient(app) as client:
        assert client.post("/api/setup", json=ADMIN).status_code == 201
        assert client.post("/api/auth/login", json=ADMIN).status_code == 204
        scan_id = client.post("/api/scans", json={"target": "https://example.com"}).json()["id"]

        scan = _wait_until(client, scan_id, "failed")

    assert scan["error"] == stored
    # the column itself, because the response is bounded again when it is served
    with Session(web_engine) as session:
        row = session.get(Scan, scan_id)
        assert row is not None and row.error == stored


def test_an_older_error_row_is_bounded_when_it_is_served(
    auth_client: TestClient, web_engine: Engine
) -> None:
    """A long message stored before the bound existed comes back within it."""
    with Session(web_engine) as session:
        scan = Scan(
            target="https://example.com",
            mode="passive",
            scope="host",
            status=ScanStatus.FAILED,
            error="y" * 20_000,
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id

    assert (
        auth_client.get(f"/api/scans/{scan_id}").json()["error"]
        == "y" * 16 * 1024 + "...[truncated]"
    )


# ---------------------------------------------------------------------------
# The runner's log
# ---------------------------------------------------------------------------

_LOG_MARKER = "hostilemarker"


async def _run_to_the_end(engine: Engine, factory: Callable[[ScanConfig], Any]) -> ScanStatus:
    """
    Args:
        engine (Engine): The per-test database engine.
        factory (Callable[[ScanConfig], Any]): Builds what runs the scan.

    Returns:
        ScanStatus: The final status of one scan of ``example.com`` and its subdomains.
    """
    with Session(engine) as session:
        scan = Scan(target="https://example.com/", mode="passive", scope="subdomains", options={})
        session.add(scan)
        session.commit()
        scan_id = scan.id
    runner = ScanRunner(engine, orchestrator_factory=factory)
    await runner.start()
    try:
        runner.wake()
        for _ in range(2_000):
            with Session(engine) as session:
                row = session.get(Scan, scan_id)
                assert row is not None
                status = ScanStatus(row.status)
            if status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                return status
            await asyncio.sleep(0.005)
    finally:
        await runner.stop()
    raise AssertionError(f"scan {scan_id} did not finish")


async def test_the_runner_logs_nothing_of_a_hostile_robots_file(
    web_engine: Engine, httpx_mock: HttpxMock, caplog: pytest.LogCaptureFixture
) -> None:
    """The file reaches the real engine, the scan completes, and no line of it is logged."""
    body = (
        f"User-agent: {_LOG_MARKER}\nDisallow: /{_LOG_MARKER}%zz\n"
        f"User-agent: *\nAllow: *{_LOG_MARKER}$\nDisallow: /{_LOG_MARKER}\n"
        f"Crawl-delay: {_LOG_MARKER}\nRequest-rate: {_LOG_MARKER}\n{_LOG_MARKER}\n"
        f"Sitemap: https://--xn--{_LOG_MARKER}.example.com/s.xml\n"
    )

    def answer(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/robots.txt":
            return httpx2.Response(200, headers={"content-type": "text/plain"}, text=body)
        page = "<html><body>ok</body></html>"
        return httpx2.Response(200, headers={"content-type": "text/html"}, text=page)

    httpx_mock.add_callback(answer, is_reusable=True)

    def real(config: ScanConfig) -> Orchestrator:
        return Orchestrator(config.with_overrides(scan={"max_pages": 3}, http={"delay_ms": 0}))

    with caplog.at_level(logging.DEBUG):
        status = await _run_to_the_end(web_engine, real)

    assert status is ScanStatus.COMPLETED
    asked = [str(request.url) for request in httpx_mock.get_requests()]
    assert "https://example.com/robots.txt" in asked  # the file was read
    assert not any(_LOG_MARKER in url for url in asked)
    assert _LOG_MARKER not in caplog.text


async def test_the_runner_log_does_show_an_error_that_escapes_a_scan(
    web_engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """The control of the test above: this capture would have seen the text."""

    class _Crashing:
        """Stands in for an engine that raises."""

        async def run(self, _target: str) -> ScanResult:
            """
            Args:
                _target (str): The scan target.

            Returns:
                ScanResult: Never returned.

            Raises:
                RuntimeError: Always, with the marker.
            """
            raise RuntimeError(_LOG_MARKER)

    with caplog.at_level(logging.DEBUG):
        status = await _run_to_the_end(web_engine, lambda _config: _Crashing())

    assert status is ScanStatus.FAILED
    assert _LOG_MARKER in caplog.text
