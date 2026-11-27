"""
Every Web API response tells caches not to store it (``Cache-Control: no-store``).

The answers that carry a user's data (the scan list, a scan, a report in each format) are
checked, and so are the refusals of the outer middlewares, which the header must reach too. A
response that sets its own ``Cache-Control`` keeps it, checked on a throwaway app.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from tests.api.conftest import ADMIN
from webvigil.api.body_limit import MAX_BODY_BYTES
from webvigil.api.cache_control import NoStoreMiddleware

# ---------------------------------------------------------------------------
# What a signed-in user reads
# ---------------------------------------------------------------------------


def _completed_scan(client: TestClient) -> int:
    """
    Args:
        client (TestClient): A signed-in client.

    Returns:
        int: The id of a freshly created scan, once it reaches ``completed``.
    """
    scan_id = client.post("/api/scans", json={"target": "https://example.com"}).json()["id"]
    deadline = time.time() + 5
    while time.time() < deadline:
        if client.get(f"/api/scans/{scan_id}").json()["status"] == "completed":
            return int(scan_id)
        time.sleep(0.05)
    raise AssertionError("scan did not complete")


def test_the_data_of_a_signed_in_user_is_not_stored(auth_client: TestClient) -> None:
    """The scan list, a scan, its findings and the session's identity all say ``no-store``."""
    scan_id = _completed_scan(auth_client)
    paths = (
        "/api/scans",
        f"/api/scans/{scan_id}",
        f"/api/scans/{scan_id}/findings",
        "/api/auth/me",
        "/api/checks",
    )
    for path in paths:
        response = auth_client.get(path)
        assert response.status_code == 200, path
        assert response.headers["cache-control"] == "no-store", path


@pytest.mark.parametrize("fmt", ["json", "sarif", "html", "md"])
def test_a_report_is_not_stored(auth_client: TestClient, fmt: str) -> None:
    """Each report format, downloaded or previewed, says ``no-store``."""
    scan_id = _completed_scan(auth_client)
    for download in ("true", "false"):
        url = f"/api/scans/{scan_id}/report?format={fmt}&download={download}"
        response = auth_client.get(url)
        assert response.status_code == 200, url
        assert response.headers["cache-control"] == "no-store", url


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------


def test_the_refusals_of_every_layer_are_not_stored(client: TestClient) -> None:
    """A 401, a 422, a 413 from the body limit and a 400 from the host check say ``no-store``."""
    assert client.post("/api/setup", json=ADMIN).status_code == 201
    unauthenticated = client.get("/api/scans")
    invalid = client.post("/api/auth/login", json={"username": "admin"})
    oversized = client.post(
        "/api/auth/login",
        content=b"x",
        headers={"Content-Length": str(MAX_BODY_BYTES + 1), "Content-Type": "application/json"},
    )
    foreign_host = client.get("/api/health", headers={"Host": "attacker.example"})
    for response, expected in (
        (unauthenticated, 401),
        (invalid, 422),
        (oversized, 413),
        (foreign_host, 400),
    ):
        assert response.status_code == expected
        assert response.headers["cache-control"] == "no-store", expected


# ---------------------------------------------------------------------------
# The middleware alone
# ---------------------------------------------------------------------------


def test_a_response_keeps_its_own_cache_control() -> None:
    """The middleware adds the header only where none is set, and never a second one."""

    async def cached(_request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok", headers={"Cache-Control": "max-age=60"})

    async def plain(_request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/cached", cached), Route("/plain", plain)])
    app.add_middleware(NoStoreMiddleware)
    with TestClient(app) as test_client:
        kept = test_client.get("/cached")
        added = test_client.get("/plain")
    assert kept.headers.get_list("cache-control") == ["max-age=60"]
    assert added.headers.get_list("cache-control") == ["no-store"]
