"""
The ``Host`` check of the Web API (GHSA-q373-8m5q-qwww).

Real app through ``TestClient``. The fixture config answers for ``testserver`` (the client's own
``Host``); every other name must be one the server knows: an IP address, ``localhost``, the bind
host or an entry of ``web.allowed_hosts``. The dashboard's proxy sends the browser's ``Host`` as
``X-Forwarded-Host``, so that header is held to the same rule.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.api.conftest import ADMIN, FakeOrchestrator
from webvigil.api.app import create_app
from webvigil.api.config import WebConfig

_REFUSED = {"detail": "host not allowed"}
_UNKNOWN = "unknown-name.example"


def test_an_unknown_host_name_is_refused(client: TestClient) -> None:
    """A request addressed to a name the server was not told about gets 400, read or write."""
    for host in (_UNKNOWN, f"{_UNKNOWN}:8000", f"{_UNKNOWN.upper()}:8000"):
        response = client.get("/api/health", headers={"Host": host})
        assert response.status_code == 400, host
        assert response.json() == _REFUSED


def test_setup_cannot_be_done_through_an_unknown_host_name(client: TestClient) -> None:
    """A fresh instance does not create its account for a request addressed to an unknown name."""
    response = client.post(
        "/api/setup", json=ADMIN, headers={"Host": _UNKNOWN, "Origin": f"http://{_UNKNOWN}"}
    )
    assert response.status_code == 400
    assert client.get("/api/setup").json()["needs_setup"] is True


def test_login_cannot_be_tried_through_an_unknown_host_name(auth_client: TestClient) -> None:
    """The login is not even attempted, so it costs no Argon2 check and no throttle slot."""
    response = auth_client.post(
        "/api/auth/login", json=ADMIN, headers={"Host": _UNKNOWN, "Origin": f"http://{_UNKNOWN}"}
    )
    assert response.status_code == 400


def test_an_unknown_forwarded_host_is_refused(auth_client: TestClient) -> None:
    """Through the dashboard's proxy the browser's Host arrives as X-Forwarded-Host."""
    headers = {"X-Forwarded-Host": f"{_UNKNOWN}:3000", "Origin": f"http://{_UNKNOWN}:3000"}
    assert auth_client.get("/api/auth/me", headers=headers).status_code == 400
    assert auth_client.post("/api/auth/logout", headers=headers).status_code == 400
    assert auth_client.get("/api/auth/me").status_code == 200


def test_a_repeated_header_is_checked_in_every_occurrence(client: TestClient) -> None:
    """One good value does not vouch for a second, unknown one."""
    headers = [("x-forwarded-host", "localhost:3000"), ("x-forwarded-host", _UNKNOWN)]
    assert client.get("/api/health", headers=headers).status_code == 400


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "localhost:8000",
        "LOCALHOST.",
        "127.0.0.1",
        "127.0.0.1:8000",
        "[::1]:8000",
        "[::1]",
        "192.168.0.10:8000",
    ],
)
def test_ip_addresses_and_localhost_are_accepted(client: TestClient, host: str) -> None:
    """A page can only have an IP address as its origin if that address served it."""
    assert client.get("/api/health", headers={"Host": host}).status_code == 200


def test_the_dashboard_on_localhost_still_works(auth_client: TestClient) -> None:
    """The proxied dashboard: the API's own Host plus the browser's in X-Forwarded-Host."""
    headers = {"X-Forwarded-Host": "localhost:3000", "Origin": "http://localhost:3000"}
    assert auth_client.get("/api/auth/me", headers=headers).status_code == 200
    assert auth_client.post("/api/auth/logout", headers=headers).status_code == 204


def test_allowed_hosts_and_a_named_bind_host_are_accepted(web_config: WebConfig) -> None:
    """``web.allowed_hosts`` (a proxy's public name, a Compose service) and ``web.host``."""
    config = web_config.model_copy(
        update={"allowed_hosts": ["testserver", "scanner.example.org", "api"], "host": "box.lan"}
    )
    with TestClient(create_app(config, orchestrator_factory=FakeOrchestrator)) as client:
        for host in ("scanner.example.org", "Scanner.Example.Org.:443", "api:8000", "box.lan"):
            assert client.get("/api/health", headers={"Host": host}).status_code == 200, host
        assert client.get("/api/health", headers={"Host": _UNKNOWN}).status_code == 400
        assert client.get("/api/health", headers={"Host": "evil.api"}).status_code == 400
