"""
Login throttling and session revocation through the real app — security audit for 1.0.0.

``TestClient`` has one client address, so a second client with another address is how the
per-username key is told apart from the per-address one. Tokens are minted by hand with
``jwt.encode`` and an issue time in the past, because the clock this feature reads has
one-second resolution and a test cannot wait for it.
"""

from __future__ import annotations

import time
from datetime import timedelta

import jwt
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from tests.api.conftest import ADMIN
from webvigil.api.config import WebConfig
from webvigil.api.db import User, session_scope, utcnow
from webvigil.api.security import SESSION_COOKIE

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


def _token(config: WebConfig, *, issued_ago: int, user_id: int = 1, with_iat: bool = True) -> str:
    """
    Args:
        config (WebConfig): Supplies the signing secret.
        issued_ago (int): How many seconds ago the token was minted.
        user_id (int): The ``sub`` claim. Defaults to 1.
        with_iat (bool): Whether to include the issue time. Defaults to ``True``.

    Returns:
        str: A valid, unexpired session token.
    """
    now = int(time.time())
    claims: dict[str, object] = {"sub": str(user_id), "exp": now + 3600}
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


# ---------------------------------------------------------------------------
# Sessions and a credential change
# ---------------------------------------------------------------------------


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
