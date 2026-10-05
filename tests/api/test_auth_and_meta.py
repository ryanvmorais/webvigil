"""
Setup, login, session, password change, and the meta routes — RF-01..06, RF-20..22.

Drives the real FastAPI app through ``TestClient``: ``client`` is a fresh app on
a per-test SQLite DB wired to a fake orchestrator, ``auth_client`` is the same
client already through first-run setup and logged in (both from
``tests/api/conftest.py``). Nothing here runs a scan.
"""

from __future__ import annotations

import time

import jwt
from fastapi.testclient import TestClient

from tests.api.conftest import ADMIN
from webvigil.checks.registry import all_checks, load_plugins

# ---------------------------------------------------------------------------
# First-run setup, login, and the session cookie
# ---------------------------------------------------------------------------


def test_setup_flow(client: TestClient) -> None:
    """First-run setup creates the admin once; ``needs_setup`` flips and a second setup is 409."""
    assert client.get("/api/setup").json() == {"needs_setup": True, "authenticated": False}
    assert client.post("/api/setup", json=ADMIN).status_code == 201
    assert client.get("/api/setup").json() == {"needs_setup": False, "authenticated": False}
    # a second setup is rejected
    assert (
        client.post("/api/setup", json={"username": "b", "password": "password123"}).status_code
        == 409
    )


def test_setup_status_reports_the_session_without_a_401(client: TestClient) -> None:
    """
    ``authenticated`` is the answer to "am I signed in?" for the login page: it follows
    the session cookie and is a 200 either way, because a 401 would show up as a console
    error in the browser (Lighthouse ``errors-in-console``).
    """
    client.post("/api/setup", json=ADMIN)

    anonymous = client.get("/api/setup")
    assert anonymous.status_code == 200
    assert anonymous.json()["authenticated"] is False

    client.post("/api/auth/login", json=ADMIN)
    assert client.get("/api/setup").json()["authenticated"] is True

    client.post("/api/auth/logout")
    client.cookies.clear()
    assert client.get("/api/setup").json()["authenticated"] is False


def test_setup_status_treats_a_bad_cookie_as_anonymous(
    client: TestClient, web_config: object
) -> None:
    """A garbage, expired, or unknown-user cookie is ``authenticated: false``, not an error."""
    client.post("/api/setup", json=ADMIN)
    secret = web_config.session_secret  # type: ignore[attr-defined]
    bad_cookies = {
        "garbage": "not-a-token",
        "expired": jwt.encode({"sub": "1", "exp": int(time.time()) - 10}, secret, "HS256"),
        "unknown user": jwt.encode({"sub": "999", "exp": int(time.time()) + 600}, secret, "HS256"),
    }
    for name, cookie in bad_cookies.items():
        client.cookies.set("webvigil_session", cookie)
        response = client.get("/api/setup")
        assert response.status_code == 200, name
        assert response.json()["authenticated"] is False, name


def test_setup_rejects_a_short_password(client: TestClient) -> None:
    """A too-short password is a 422 at setup."""
    assert client.post("/api/setup", json={"username": "a", "password": "short"}).status_code == 422


def test_login_sets_a_cookie_and_bad_credentials_do_not(client: TestClient) -> None:
    """A good login sets the session cookie; bad credentials are 401 with no cookie."""
    client.post("/api/setup", json=ADMIN)
    ok = client.post("/api/auth/login", json=ADMIN)
    assert ok.status_code == 204
    assert "webvigil_session" in ok.cookies

    client.cookies.clear()
    bad = client.post("/api/auth/login", json={"username": "admin", "password": "nope"})
    assert bad.status_code == 401
    assert "webvigil_session" not in bad.cookies


def test_protected_route_needs_a_session(client: TestClient) -> None:
    """A protected route with no session cookie is 401."""
    assert client.get("/api/auth/me").status_code == 401


def test_me_returns_the_user(auth_client: TestClient) -> None:
    """``/api/auth/me`` returns the logged-in user's username and id."""
    body = auth_client.get("/api/auth/me").json()
    assert body["username"] == "admin"
    assert "id" in body


def test_logout_clears_the_cookie(auth_client: TestClient) -> None:
    """After logout the session no longer authenticates."""
    assert auth_client.post("/api/auth/logout").status_code == 204
    auth_client.cookies.clear()
    assert auth_client.get("/api/auth/me").status_code == 401


def test_password_change(auth_client: TestClient) -> None:
    """A wrong current password is 403; a correct one changes it and the new password logs in."""
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
    """A session cookie whose ``exp`` is in the past no longer authenticates."""
    stale = jwt.encode(
        {"sub": "1", "exp": int(time.time()) - 10},
        web_config.session_secret,  # type: ignore[attr-defined]
        algorithm="HS256",
    )
    auth_client.cookies.set("webvigil_session", stale)
    assert auth_client.get("/api/auth/me").status_code == 401


# ---------------------------------------------------------------------------
# The meta routes: health, checks, config defaults
# ---------------------------------------------------------------------------


def test_health_needs_no_auth(client: TestClient) -> None:
    """``/api/health`` is reachable without a session and reports status and version."""
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["version"]


def test_checks_matches_the_registry(auth_client: TestClient) -> None:
    """``/api/checks`` lists exactly the registered check ids."""
    load_plugins()
    body = auth_client.get("/api/checks").json()
    assert {c["id"] for c in body} == {check.id for check in all_checks()}


def test_config_defaults(auth_client: TestClient) -> None:
    """``/api/config/defaults`` returns the engine's default scan settings."""
    body = auth_client.get("/api/config/defaults").json()
    assert body["mode"] == "passive"
    assert body["scope"] == "host"
    assert body["max_pages"] == 50
