"""
Password hashing, JWT session tokens, and the session cookie (RF-02..RF-07).

Every password and the signing secret arrive as :class:`~webvigil.core.secrets.Secret` values
(spec 024): the four functions that hash, verify, sign and check are the only places in the Web
API that reveal one.
"""

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
from sqlalchemy import Engine, update
from sqlmodel import Session, col

from webvigil.api.config import WebConfig
from webvigil.api.db import Setting, User, session_scope, utcnow
from webvigil.core.secrets import Secret, SecretKind

logger = logging.getLogger("webvigil.api")

_hasher = PasswordHasher()
_ALGORITHM = "HS256"
SESSION_COOKIE = "webvigil_session"


def hash_password(password: Secret) -> str:
    """
    Args:
        password (Secret): The password.

    Returns:
        str: An Argon2 hash string (algorithm, parameters, salt, and digest).
    """
    return _hasher.hash(password.reveal())


def verify_password(password: Secret, hashed: str) -> bool:
    """
    Args:
        password (Secret): The password to check.
        hashed (str): The stored Argon2 hash.

    Returns:
        bool: ``True`` when the password matches; ``False`` on mismatch or a
            malformed hash.
    """
    try:
        _hasher.verify(hashed, password.reveal())
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
    return hash_password(Secret(secrets.token_urlsafe(32), kind=SecretKind.PASSWORD))


def create_token(
    user_id: int, secret: Secret, ttl_hours: int, *, issued_at: datetime | None = None
) -> str:
    """
    Mint a signed session token.

    The issue time keeps its fractional seconds (RFC 7519 allows a non-integer NumericDate): a
    session is rejected when it was issued before the credentials last changed, and whole seconds
    would let a token minted earlier in the same second as a password change survive it.

    Args:
        user_id (int): The user the token authenticates.
        secret (Secret): The HS256 signing secret.
        ttl_hours (int): Token lifetime, in hours.
        issued_at (datetime | None): The issue time, timezone-aware. A password change passes the
            moment it stored as ``User.updated_at``, so the fresh cookie is never older than the
            change it follows, and a login the moment before it read the hash, so a change that
            lands while the password is being verified ends this session too. Defaults to now.

    Returns:
        str: The encoded JWT.
    """
    now = issued_at if issued_at is not None else datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "iat": now.timestamp(),
        "exp": now + timedelta(hours=ttl_hours),
    }
    return jwt.encode(payload, secret.reveal(), algorithm=_ALGORITHM)


class TokenClaims(NamedTuple):
    """
    What a valid session token says.

    Attributes:
        user_id (int): The user the token authenticates.
        issued_at (float): When it was minted, in seconds since the epoch.
    """

    user_id: int
    issued_at: float


def decode_token(token: str, secret: Secret) -> TokenClaims | None:
    """
    Args:
        token (str): A session JWT.
        secret (Secret): The HS256 signing secret.

    Returns:
        TokenClaims | None: The claims of a valid, unexpired, well-formed token that carries a
            subject, an issue time and an expiry, or ``None``.
    """
    try:
        # A token without an expiry would never expire, and one without an issue time could not
        # be compared with the last credential change: both are refused, not defaulted.
        payload = jwt.decode(
            token,
            secret.reveal(),
            algorithms=[_ALGORITHM],
            options={"require": ["exp", "iat", "sub"]},
        )
        return TokenClaims(user_id=int(payload["sub"]), issued_at=float(payload["iat"]))
    except (jwt.PyJWTError, KeyError, ValueError, TypeError):
        return None


def credentials_stamp(user: User) -> datetime:
    """
    When the user's credentials last changed: a password change or ``reset-password``.

    ``User.updated_at`` is set by exactly those two paths. SQLite hands the timestamp back without
    a zone; it is UTC, and reading it as local time would shift it by the machine's offset.

    Args:
        user (User): The user row.

    Returns:
        datetime: That moment, timezone-aware.
    """
    stamp = user.updated_at
    return stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp


def credentials_changed_at(user: User) -> float:
    """
    :func:`credentials_stamp` as a number: a token minted before it is no longer accepted.

    Args:
        user (User): The user row.

    Returns:
        float: That moment, in seconds since the epoch, with its fractional part.
    """
    return credentials_stamp(user).timestamp()


def store_password_hash(
    session: Session, user_id: int, new_hash: str, *, expected_hash: str | None = None
) -> datetime | None:
    """
    Replace the stored hash and end every session issued against the old one.

    Written in two commits, because a reader keeps seeing the old hash until the first one lands:
    a login that read it began before that commit, so only a stamp taken *after* the commit is
    certain to be later than that login's token. The extra microsecond keeps the two apart on a
    clock too coarse to tell them.

    Args:
        session (Session): The session to write with. It is committed.
        user_id (int): The user whose password changes.
        new_hash (str): The new Argon2 hash.
        expected_hash (str | None): Write only if this is still the stored hash, so that of two
            changes that verified the same password one cannot overwrite the other. Defaults to
            an unconditional write.

    Returns:
        datetime | None: The moment stored as the change, for the caller's fresh token; ``None``
            when the stored hash was no longer ``expected_hash``, or when another change replaced
            this hash before it was stamped: the password just written is then not the current
            one, and no token may be issued for it.
    """
    swap = update(User).where(col(User.id) == user_id)
    if expected_hash is not None:
        swap = swap.where(col(User.password_hash) == expected_hash)
    swapped_at = utcnow()
    written = session.exec(swap.values(password_hash=new_hash, updated_at=swapped_at))
    session.commit()
    if written.rowcount != 1:
        return None
    changed_at = max(utcnow(), swapped_at) + timedelta(microseconds=1)
    # Only over this very hash: a later change has already stamped a later moment.
    stamped = session.exec(
        update(User)
        .where(col(User.id) == user_id, col(User.password_hash) == new_hash)
        .values(updated_at=changed_at)
    )
    session.commit()
    return changed_at if stamped.rowcount == 1 else None


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


def resolve_session_secret(engine: Engine, config: WebConfig) -> Secret:
    """
    Determine the JWT signing secret for this process.

    Args:
        engine (Engine): The DB engine, for the stored fallback.
        config (WebConfig): Supplies the pinned secret, if any.

    Returns:
        Secret: ``config.session_secret`` when set; otherwise the secret stored in
            the ``setting`` table; otherwise a fresh one, which is stored and
            logged as a warning. The row keeps the plain value: the database is
            where it is stored.
    """
    if config.session_secret:
        return config.session_secret
    with session_scope(engine) as session:
        row = session.get(Setting, "session_secret")
        if row is not None:
            return Secret(row.value, kind=SecretKind.SIGNING_KEY)
        value = secrets.token_urlsafe(48)
        session.add(Setting(key="session_secret", value=value))
    logger.warning(
        "generated a session signing secret and stored it in the database; "
        "set web.session_secret to pin it"
    )
    return Secret(value, kind=SecretKind.SIGNING_KEY)
