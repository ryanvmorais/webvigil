"""
The ``Origin`` check on state-changing requests of the Web API — issue #162.

Real app through ``TestClient``, no mocks. The client's own host is ``testserver``, so
``http://testserver`` is "the request's own origin". The dashboard case is the one that must keep
working: Next rewrites ``/api/*`` to the API with the API's ``Host``, and the browser's ``Origin``
(the dashboard) only matches the ``X-Forwarded-Host`` the proxy adds, which a test sends by hand.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.api.conftest import FakeOrchestrator
from webvigil.api.app import create_app
from webvigil.api.config import WebConfig

_FOREIGN = {"Origin": "https://evil.example"}
_REFUSED = {"detail": "cross-origin request refused"}


def test_a_foreign_origin_cannot_log_out(auth_client: TestClient) -> None:
    """A bodyless POST from another origin is refused, and the session survives it."""
    response = auth_client.post("/api/auth/logout", headers=_FOREIGN)
    assert response.status_code == 403
    assert response.json() == _REFUSED
    assert auth_client.get("/api/auth/me").status_code == 200


def test_a_foreign_origin_cannot_create_or_cancel_a_scan(auth_client: TestClient) -> None:
    """A scan is neither created nor cancelled by a request from another origin."""
    body = {"target": "https://example.com/"}
    assert auth_client.post("/api/scans", json=body, headers=_FOREIGN).status_code == 403
    assert auth_client.post("/api/scans/1/cancel", headers=_FOREIGN).status_code == 403
    assert auth_client.get("/api/scans").json()["items"] == []


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
def test_every_state_changing_method_is_checked(auth_client: TestClient, method: str) -> None:
    """PUT, PATCH and DELETE are refused too, before routing (so even an unknown route)."""
    assert auth_client.request(method, "/api/scans/1", headers=_FOREIGN).status_code == 403


def test_a_request_without_origin_is_untouched(auth_client: TestClient) -> None:
    """curl, the CLI and server-to-server calls send no Origin and are not affected."""
    assert auth_client.post("/api/auth/logout").status_code == 204


def test_the_servers_own_origin_is_accepted(auth_client: TestClient) -> None:
    """An Origin naming the host the request was addressed to passes, scheme case aside."""
    for origin in ("http://testserver", "HTTP://TestServer", "http://testserver/"):
        response = auth_client.post("/api/auth/logout", headers={"Origin": origin})
        assert response.status_code == 204, origin


def test_another_port_of_the_same_host_is_foreign(auth_client: TestClient) -> None:
    """Same host, other port: not the same origin (and not the same server)."""
    response = auth_client.post("/api/auth/logout", headers={"Origin": "http://testserver:3000"})
    assert response.status_code == 403


def test_the_dashboards_origin_matches_the_forwarded_host(auth_client: TestClient) -> None:
    """Behind the Next proxy the Origin is the dashboard's: it matches X-Forwarded-Host."""
    headers = {"Origin": "https://dashboard.example", "X-Forwarded-Host": "dashboard.example"}
    assert auth_client.post("/api/auth/logout", headers=headers).status_code == 204


def test_a_forwarded_host_does_not_vouch_for_another_origin(auth_client: TestClient) -> None:
    """Only the forwarded host itself is accepted, not any Origin that arrives with the header."""
    headers = {"Origin": "https://evil.example", "X-Forwarded-Host": "dashboard.example"}
    assert auth_client.post("/api/auth/logout", headers=headers).status_code == 403


@pytest.mark.parametrize("origin", ["null", "not a url", "evil.example", "https://", "file:///x"])
def test_an_opaque_or_malformed_origin_is_refused(auth_client: TestClient, origin: str) -> None:
    """``null`` (a sandboxed frame) and anything that is not an origin never passes."""
    assert auth_client.post("/api/auth/logout", headers={"Origin": origin}).status_code == 403


def test_a_safe_method_is_never_checked(auth_client: TestClient) -> None:
    """Reading is not state-changing: GET from another origin is up to CORS and the cookie."""
    assert auth_client.get("/api/auth/me", headers=_FOREIGN).status_code == 200


def test_cors_origins_are_accepted_and_others_are_not(web_config: WebConfig) -> None:
    """An origin the operator listed in ``cors_origins`` passes; a different one does not."""
    config = web_config.model_copy(update={"cors_origins": ["https://ui.example"]})
    with TestClient(create_app(config, orchestrator_factory=FakeOrchestrator)) as client:
        admin = {"username": "admin", "password": "password123"}
        assert client.post("/api/setup", json=admin).status_code == 201
        assert client.post("/api/auth/login", json=admin).status_code == 204
        listed = client.post("/api/auth/logout", headers={"Origin": "https://UI.example/"})
        assert listed.status_code == 204
        assert client.post("/api/auth/logout", headers=_FOREIGN).status_code == 403
