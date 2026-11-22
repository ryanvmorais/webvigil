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
from webvigil import __version__
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

    client.post("/api/auth/logout")  # its answer deletes the cookie
    assert client.get("/api/setup").json()["authenticated"] is False


def test_setup_status_treats_a_bad_cookie_as_anonymous(
    client: TestClient, web_config: object
) -> None:
    """A garbage, expired, or unknown-user cookie is ``authenticated: false``, not an error."""
    client.post("/api/setup", json=ADMIN)
    secret = web_config.session_secret  # type: ignore[attr-defined]
    now = time.time()  # after the account was created, so no token below predates it

    def token(**claims: object) -> str:
        """
        Args:
            **claims (object): The claims that differ from a valid session for user 1.

        Returns:
            str: The signed token.
        """
        return jwt.encode({"sub": "1", "iat": now, "exp": int(now) + 600, **claims}, secret)

    # Each token differs from the control only in what its name says, so it is refused for that
    # reason and not for a missing claim.
    bad_cookies = {
        "garbage": "not-a-token",
        "expired": token(exp=int(now) - 10),
        "unknown user": token(sub="999"),
    }
    for name, cookie in bad_cookies.items():
        client.cookies.set("webvigil_session", cookie)
        response = client.get("/api/setup")
        assert response.status_code == 200, name
        assert response.json()["authenticated"] is False, name
    client.cookies.set("webvigil_session", token())  # control: the same token, valid
    assert client.get("/api/setup").json()["authenticated"] is True


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
    assert (body["id"], body["username"]) == (1, "admin")


def test_logout_clears_the_cookie(auth_client: TestClient) -> None:
    """
    The logout answer deletes the session cookie, so the browser stops sending it (RF-03).

    The token is a stateless JWT (ADR-4 of spec 002): clearing the cookie is all a logout does, so
    the jar is left to the answer, never emptied by hand.
    """
    assert "webvigil_session" in auth_client.cookies
    response = auth_client.post("/api/auth/logout")
    assert response.status_code == 204
    deletion = response.headers["set-cookie"]
    assert deletion.startswith("webvigil_session=") and "Max-Age=0" in deletion
    assert "Path=/" in deletion
    assert "webvigil_session" not in auth_client.cookies
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
    secret = web_config.session_secret  # type: ignore[attr-defined]
    now = time.time()  # after the login, so the token does not predate the account

    def token(exp: int) -> str:
        """
        Args:
            exp (int): The expiry, in seconds since the epoch.

        Returns:
            str: A session token for user 1, issued now.
        """
        return jwt.encode({"sub": "1", "iat": now, "exp": exp}, secret, algorithm="HS256")

    # Replace the login cookie rather than add a second one: with both, the outcome would depend on
    # the order the client sends them in.
    auth_client.cookies.clear()
    auth_client.cookies.set("webvigil_session", token(int(now) - 10))
    assert auth_client.get("/api/auth/me").status_code == 401
    auth_client.cookies.set("webvigil_session", token(int(now) + 600))  # control: not expired
    assert auth_client.get("/api/auth/me").status_code == 200


# ---------------------------------------------------------------------------
# The meta routes: health, checks, config defaults
# ---------------------------------------------------------------------------


def test_health_needs_no_auth(client: TestClient) -> None:
    """``/api/health`` is reachable without a session and reports status and version."""
    assert client.get("/api/health").json() == {"status": "ok", "version": __version__}


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
