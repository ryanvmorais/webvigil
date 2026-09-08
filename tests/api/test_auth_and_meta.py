"""
Setup, login, session, password change, and the meta routes — RF-01..06, RF-20..22.
"""

from __future__ import annotations

import time

import jwt
from fastapi.testclient import TestClient

from tests.api.conftest import ADMIN
from webvigil.checks.registry import all_checks, load_plugins


def test_setup_flow(client: TestClient) -> None:
    assert client.get("/api/setup").json() == {"needs_setup": True}
    assert client.post("/api/setup", json=ADMIN).status_code == 201
    assert client.get("/api/setup").json() == {"needs_setup": False}
    # a second setup is rejected
    assert (
        client.post("/api/setup", json={"username": "b", "password": "password123"}).status_code
        == 409
    )


def test_setup_rejects_a_short_password(client: TestClient) -> None:
    assert client.post("/api/setup", json={"username": "a", "password": "short"}).status_code == 422


def test_login_sets_a_cookie_and_bad_credentials_do_not(client: TestClient) -> None:
    client.post("/api/setup", json=ADMIN)
    ok = client.post("/api/auth/login", json=ADMIN)
    assert ok.status_code == 204
    assert "webvigil_session" in ok.cookies

    client.cookies.clear()
    bad = client.post("/api/auth/login", json={"username": "admin", "password": "nope"})
    assert bad.status_code == 401
    assert "webvigil_session" not in bad.cookies


def test_protected_route_needs_a_session(client: TestClient) -> None:
    assert client.get("/api/auth/me").status_code == 401


def test_me_returns_the_user(auth_client: TestClient) -> None:
    body = auth_client.get("/api/auth/me").json()
    assert body["username"] == "admin"
    assert "id" in body


def test_logout_clears_the_cookie(auth_client: TestClient) -> None:
    assert auth_client.post("/api/auth/logout").status_code == 204
    auth_client.cookies.clear()
    assert auth_client.get("/api/auth/me").status_code == 401


def test_password_change(auth_client: TestClient) -> None:
    wrong = auth_client.post(
        "/api/auth/password", json={"current_password": "nope", "new_password": "brandnew123"}
    )
    assert wrong.status_code == 403

    ok = auth_client.post(
        "/api/auth/password",
        json={"current_password": ADMIN["password"], "new_password": "brandnew123"},
    )
    assert ok.status_code == 204
    auth_client.cookies.clear()
    assert (
        auth_client.post(
            "/api/auth/login", json={"username": "admin", "password": "brandnew123"}
        ).status_code
        == 204
    )


def test_expired_cookie_is_rejected(auth_client: TestClient, web_config: object) -> None:
    stale = jwt.encode(
        {"sub": "1", "exp": int(time.time()) - 10},
        web_config.session_secret,  # type: ignore[attr-defined]
        algorithm="HS256",
    )
    auth_client.cookies.set("webvigil_session", stale)
    assert auth_client.get("/api/auth/me").status_code == 401


def test_health_needs_no_auth(client: TestClient) -> None:
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["version"]


def test_checks_matches_the_registry(auth_client: TestClient) -> None:
    load_plugins()
    body = auth_client.get("/api/checks").json()
    assert {c["id"] for c in body} == {check.id for check in all_checks()}


def test_config_defaults(auth_client: TestClient) -> None:
    body = auth_client.get("/api/config/defaults").json()
    assert body["mode"] == "passive"
    assert body["scope"] == "host"
    assert body["max_pages"] == 50
