"""Password hashing, JWT session tokens, and the session cookie (RF-02..RF-07)."""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Response
from sqlalchemy import Engine

from webvigil.api.config import WebConfig
from webvigil.api.db import Setting, session_scope

logger = logging.getLogger("webvigil.api")

_hasher = PasswordHasher()
_ALGORITHM = "HS256"
SESSION_COOKIE = "webvigil_session"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        _hasher.verify(hashed, password)
    except (VerificationError, InvalidHashError):
        return False
    return True


def create_token(user_id: int, secret: str, ttl_hours: int) -> str:
    now = datetime.now(UTC)
    payload = {"sub": str(user_id), "iat": now, "exp": now + timedelta(hours=ttl_hours)}
    return jwt.encode(payload, secret, algorithm=_ALGORITHM)


def decode_token(token: str, secret: str) -> int | None:
    """Return the user id in a valid, unexpired token, or ``None``."""
    try:
        payload = jwt.decode(token, secret, algorithms=[_ALGORITHM])
        return int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError, TypeError):
        return None


def set_session_cookie(response: Response, token: str, config: WebConfig) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=config.session_ttl_hours * 3600,
        httponly=True,
        samesite="lax",
        secure=config.cookie_secure,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


def resolve_session_secret(engine: Engine, config: WebConfig) -> str:
    """Pinned secret from config, else the stored one, else a freshly generated + stored one."""
    if config.session_secret:
        return config.session_secret
    with session_scope(engine) as session:
        row = session.get(Setting, "session_secret")
        if row is not None:
            return row.value
        secret = secrets.token_urlsafe(48)
        session.add(Setting(key="session_secret", value=secret))
    logger.warning(
        "generated a session signing secret and stored it in the database; "
        "set web.session_secret to pin it"
    )
    return secret
