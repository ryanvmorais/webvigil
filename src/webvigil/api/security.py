"""Password hashing, JWT session tokens, and the session cookie (RF-02..RF-07)."""

from __future__ import annotations

import functools
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import NamedTuple

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Response
from sqlalchemy import Engine

from webvigil.api.config import WebConfig
from webvigil.api.db import Setting, User, session_scope

logger = logging.getLogger("webvigil.api")

_hasher = PasswordHasher()
_ALGORITHM = "HS256"
SESSION_COOKIE = "webvigil_session"


def hash_password(password: str) -> str:
    """
    Args:
        password (str): The plaintext password.

    Returns:
        str: An Argon2 hash string (algorithm, parameters, salt, and digest).
    """
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """
    Args:
        password (str): The plaintext password to check.
        hashed (str): The stored Argon2 hash.

    Returns:
        bool: ``True`` when the password matches; ``False`` on mismatch or a
            malformed hash.
    """
    try:
        _hasher.verify(hashed, password)
    except (VerificationError, InvalidHashError):
        return False
    return True


@functools.cache
def dummy_password_hash() -> str:
    """
    A hash that nobody knows the password of, built once with the same parameters as a real one.

    Login verifies against it when the username does not exist, so an unknown user costs one Argon2
    check like a wrong password does, and the response time does not tell the two apart. It is
    computed on first use and warmed at startup, so the first unknown user is not slower either.

    Returns:
        str: An Argon2 hash string of a random, discarded password.
    """
    return hash_password(secrets.token_urlsafe(32))


def create_token(
    user_id: int, secret: str, ttl_hours: int, *, issued_at: datetime | None = None
) -> str:
    """
    Mint a signed session token.

    The issue time keeps its fractional seconds (RFC 7519 allows a non-integer NumericDate): a
    session is rejected when it was issued before the credentials last changed, and whole seconds
    would let a token minted earlier in the same second as a password change survive it.

    Args:
        user_id (int): The user the token authenticates.
        secret (str): The HS256 signing secret.
        ttl_hours (int): Token lifetime, in hours.
        issued_at (datetime | None): The issue time, timezone-aware. A password change passes the
            moment it stored as ``User.updated_at``, so the fresh cookie is never older than the
            change it follows. Defaults to now.

    Returns:
        str: The encoded JWT.
    """
    now = issued_at if issued_at is not None else datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "iat": now.timestamp(),
        "exp": now + timedelta(hours=ttl_hours),
    }
    return jwt.encode(payload, secret, algorithm=_ALGORITHM)


class TokenClaims(NamedTuple):
    """
    What a valid session token says.

    Attributes:
        user_id (int): The user the token authenticates.
        issued_at (float): When it was minted, in seconds since the epoch.
    """

    user_id: int
    issued_at: float


def decode_token(token: str, secret: str) -> TokenClaims | None:
    """
    Args:
        token (str): A session JWT.
        secret (str): The HS256 signing secret.

    Returns:
        TokenClaims | None: The claims of a valid, unexpired, well-formed token that carries a
            subject, an issue time and an expiry, or ``None``.
    """
    try:
        # A token without an expiry would never expire, and one without an issue time could not
        # be compared with the last credential change: both are refused, not defaulted.
        payload = jwt.decode(
            token, secret, algorithms=[_ALGORITHM], options={"require": ["exp", "iat", "sub"]}
        )
        return TokenClaims(user_id=int(payload["sub"]), issued_at=float(payload["iat"]))
    except (jwt.PyJWTError, KeyError, ValueError, TypeError):
        return None


def credentials_changed_at(user: User) -> float:
    """
    When the user's credentials last changed: a password change or ``reset-password``.

    ``User.updated_at`` is set by exactly those two paths. A token minted before that moment was
    issued against the old credentials and is no longer accepted. SQLite hands the timestamp back
    without a zone; it is UTC, and reading it as local time would shift it by the machine's offset.

    Args:
        user (User): The user row.

    Returns:
        float: That moment, in seconds since the epoch, with its fractional part.
    """
    stamp = user.updated_at
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return stamp.timestamp()


def set_session_cookie(response: Response, token: str, config: WebConfig) -> None:
    """
    Attach the session cookie (``HttpOnly``, ``SameSite=Lax``) to ``response``.

    Args:
        response (Response): The response to set the cookie on.
        token (str): The session JWT.
        config (WebConfig): Supplies the TTL and the ``Secure`` flag.
    """
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
    """
    Delete the session cookie.

    Args:
        response (Response): The response to clear the cookie on.
    """
    response.delete_cookie(SESSION_COOKIE, path="/")


def resolve_session_secret(engine: Engine, config: WebConfig) -> str:
    """
    Determine the JWT signing secret for this process.

    Args:
        engine (Engine): The DB engine, for the stored fallback.
        config (WebConfig): Supplies the pinned secret, if any.

    Returns:
        str: ``config.session_secret`` when set; otherwise the secret stored in
            the ``setting`` table; otherwise a fresh one, which is stored and
            logged as a warning.
    """
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
