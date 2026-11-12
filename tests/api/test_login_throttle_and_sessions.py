"""
Login throttling and session revocation through the real app — security audit for 1.0.0.

``TestClient`` has one client address, so a second client with another address is how the
per-username key is told apart from the per-address one. Tokens are minted by hand with
``jwt.encode`` and an issue time in the past, so a test sets the order of the token and the
credential change without waiting for the clock.
"""

from __future__ import annotations

import time
from datetime import timedelta

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from tests.api.conftest import ADMIN
from webvigil.api.config import WebConfig
from webvigil.api.db import User, session_scope, utcnow
from webvigil.api.routes import auth as auth_routes
from webvigil.api.security import SESSION_COOKIE, dummy_password_hash

_WRONG = {"username": "admin", "password": "not-the-password"}


def _age_credentials(engine: Engine, hours: int = 1) -> None:
    """
    Args:
        engine (Engine): The app's database.
        hours (int): How far back to put the user's last credential change. Defaults to 1.
    """
    with session_scope(engine) as session:
        user = session.get(User, 1)
        assert user is not None
        user.updated_at = utcnow() - timedelta(hours=hours)


def _token(config: WebConfig, *, issued_ago: float, user_id: int = 1, with_iat: bool = True) -> str:
    """
    Args:
        config (WebConfig): Supplies the signing secret.
        issued_ago (float): How many seconds ago the token was minted.
        user_id (int): The ``sub`` claim. Defaults to 1.
        with_iat (bool): Whether to include the issue time. Defaults to ``True``.

    Returns:
        str: A valid, unexpired session token.
    """
    now = time.time()
    claims: dict[str, object] = {"sub": str(user_id), "exp": int(now) + 3600}
    if with_iat:
        claims["iat"] = now - issued_ago
    return jwt.encode(claims, config.session_secret, algorithm="HS256")


# ---------------------------------------------------------------------------
# Throttling
# ---------------------------------------------------------------------------


def test_after_five_wrong_passwords_even_the_right_one_waits(client: TestClient) -> None:
    """The sixth attempt gets 429 and ``Retry-After``, whatever the password."""
    assert client.post("/api/setup", json=ADMIN).status_code == 201
    for _ in range(5):
        assert client.post("/api/auth/login", json=_WRONG).status_code == 401
    blocked = client.post("/api/auth/login", json=ADMIN)
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) >= 1


def test_a_good_login_forgets_the_earlier_failures(client: TestClient) -> None:
    """Four mistakes then the right password: signed in, and the count starts over."""
    assert client.post("/api/setup", json=ADMIN).status_code == 201
    for _ in range(4):
        assert client.post("/api/auth/login", json=_WRONG).status_code == 401
    assert client.post("/api/auth/login", json=ADMIN).status_code == 204
    for _ in range(4):
        assert client.post("/api/auth/login", json=_WRONG).status_code == 401  # not 429 yet


def test_the_username_is_slowed_from_any_address(client: TestClient) -> None:
    """Guessing from many addresses is still slowed by the per-username key."""
    assert client.post("/api/setup", json=ADMIN).status_code == 201
    for _ in range(5):
        client.post("/api/auth/login", json=_WRONG)
    elsewhere = TestClient(client.app, client=("203.0.113.9", 4000))
    assert elsewhere.post("/api/auth/login", json=ADMIN).status_code == 429


def test_behind_the_proxy_a_strangers_failures_do_not_slow_the_owner(client: TestClient) -> None:
    """Every proxied request has the proxy's address, so only the username key counts there."""
    assert client.post("/api/setup", json=ADMIN).status_code == 201
    proxied = {"X-Forwarded-Host": "localhost"}
    stranger = {"username": "someone-else", "password": "a-guess"}
    for _ in range(6):
        client.post("/api/auth/login", json=stranger, headers=proxied)
    assert client.post("/api/auth/login", json=ADMIN, headers=proxied).status_code == 204


def test_a_direct_client_is_still_slowed_by_its_address(client: TestClient) -> None:
    """Without the proxy, failures on any username slow the address that made them."""
    assert client.post("/api/setup", json=ADMIN).status_code == 201
    for _ in range(5):
        client.post("/api/auth/login", json={"username": "someone-else", "password": "a-guess"})
    assert client.post("/api/auth/login", json=ADMIN).status_code == 429


def test_the_password_change_is_throttled_like_a_login(auth_client: TestClient) -> None:
    """A stolen session is no unlimited oracle for the current password: the sixth check waits."""
    wrong = {"current_password": "not-the-password", "new_password": "brandnew123"}
    for _ in range(5):
        assert auth_client.post("/api/auth/password", json=wrong).status_code == 403
    right = {"current_password": ADMIN["password"], "new_password": "brandnew123"}
    blocked = auth_client.post("/api/auth/password", json=right)
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) >= 1


def test_a_good_password_change_forgets_the_earlier_failures(auth_client: TestClient) -> None:
    """Four wrong checks then the right one: changed, and the count starts over."""
    wrong = {"current_password": "not-the-password", "new_password": "brandnew123"}
    for _ in range(4):
        assert auth_client.post("/api/auth/password", json=wrong).status_code == 403
    right = {"current_password": ADMIN["password"], "new_password": "brandnew123"}
    assert auth_client.post("/api/auth/password", json=right).status_code == 204
    wrong["current_password"] = "still-not-it"
    for _ in range(4):
        assert auth_client.post("/api/auth/password", json=wrong).status_code == 403


# ---------------------------------------------------------------------------
# Sessions and a credential change
# ---------------------------------------------------------------------------


def test_a_token_from_earlier_in_the_same_second_is_signed_out(
    auth_client: TestClient, web_engine: Engine, web_config: WebConfig
) -> None:
    """The change and the token are compared below the second, so the older token loses."""
    changed = utcnow().replace(microsecond=800_000) - timedelta(minutes=10)
    with session_scope(web_engine) as session:
        user = session.get(User, 1)
        assert user is not None
        user.updated_at = changed
    older = TestClient(auth_client.app)
    # Half a second before the change, inside the same whole second.
    issued_ago = time.time() - (changed.timestamp() - 0.5)
    older.cookies.set(SESSION_COOKIE, _token(web_config, issued_ago=issued_ago))
    assert older.get("/api/auth/me").status_code == 401


def test_changing_the_password_signs_the_other_sessions_out(
    auth_client: TestClient, web_engine: Engine, web_config: WebConfig
) -> None:
    """This session carries on with a fresh cookie; one minted earlier is rejected."""
    _age_credentials(web_engine)
    other = TestClient(auth_client.app)
    other.cookies.set(SESSION_COOKIE, _token(web_config, issued_ago=120))
    assert other.get("/api/auth/me").status_code == 200  # valid until the password changes

    changed = auth_client.post(
        "/api/auth/password",
        json={"current_password": ADMIN["password"], "new_password": "brandnew123"},
    )
    assert changed.status_code == 204
    assert auth_client.get("/api/auth/me").status_code == 200  # the session that changed it stays
    assert other.get("/api/auth/me").status_code == 401  # every other one is out


def test_a_token_without_an_issue_time_is_not_accepted(
    auth_client: TestClient, web_config: WebConfig
) -> None:
    """A token that cannot say when it was minted cannot be compared with the last change."""
    auth_client.cookies.set(SESSION_COOKIE, _token(web_config, issued_ago=0, with_iat=False))
    assert auth_client.get("/api/auth/me").status_code == 401


# ---------------------------------------------------------------------------
# Timing: an unknown username costs the same password check (issue #139)
# ---------------------------------------------------------------------------


def test_an_unknown_username_runs_the_same_password_check_as_a_wrong_password(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both failures verify one Argon2 hash, so the response time does not tell them apart."""
    assert client.post("/api/setup", json=ADMIN).status_code == 201
    checked: list[str] = []
    real = auth_routes.verify_password

    def _spy(password: str, hashed: str) -> bool:
        checked.append(hashed)
        return real(password, hashed)

    monkeypatch.setattr(auth_routes, "verify_password", _spy)

    wrong = client.post("/api/auth/login", json=_WRONG)
    unknown = client.post("/api/auth/login", json={"username": "nobody", "password": "x"})

    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()  # the body does not say which either
    assert len(checked) == 2  # one check each; the unknown user did not skip it
    assert checked[1] == dummy_password_hash()


def test_a_login_body_over_the_cap_is_refused_before_it_is_counted(client: TestClient) -> None:
    """
    A huge username or password is a 422 and never reaches the throttle table.

    The throttle keeps a key per failed username for 15 minutes, so an unbounded username let an
    unauthenticated client grow the process by what it sent.
    """
    app_throttle = client.app.state.login_throttle  # type: ignore[attr-defined]
    for body in (
        {"username": "a" * 65, "password": "x"},
        {"username": "admin", "password": "p" * 257},
    ):
        assert client.post("/api/auth/login", json=body).status_code == 422
    assert app_throttle._failures == {}


def test_the_caps_are_the_same_as_the_ones_setup_enforces(client: TestClient) -> None:
    """A real account always fits: 64-character names and 256-character passwords still log in."""
    account = {"username": "n" * 64, "password": "p" * 256}
    assert client.post("/api/setup", json=account).status_code == 201
    assert client.post("/api/auth/login", json=account).status_code == 204


def test_changing_the_password_caps_the_current_password(auth_client: TestClient) -> None:
    """The current password in a password change is capped like every other password field."""
    body = {"current_password": "c" * 257, "new_password": "a-new-long-password"}
    assert auth_client.post("/api/auth/password", json=body).status_code == 422
