"""Login, logout, session identity, and password change (RF-02..RF-06)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlmodel import select

from webvigil.api.client_address import client_address
from webvigil.api.db import User, utcnow
from webvigil.api.deps import CurrentUser, SessionDep
from webvigil.api.schemas import LoginIn, PasswordChangeIn, UserOut
from webvigil.api.security import (
    clear_session_cookie,
    create_token,
    credentials_stamp,
    dummy_password_hash,
    hash_password,
    set_session_cookie,
    store_password_hash,
    verify_password,
)
from webvigil.api.throttle import BUSY_RETRY_S, LoginThrottle

router = APIRouter(prefix="/auth", tags=["auth"])


def _client_key(request: Request) -> str:
    """
    Args:
        request (Request): The login request.

    Returns:
        str: ``client:<address>``, the key whose wait this client alone pays.
    """
    peer = request.client.host if request.client else None
    forwarded = request.headers.getlist("x-forwarded-for")
    return f"client:{client_address(peer, forwarded, request.app.state.trusted_proxies)}"


def _too_many(wait: int, what: str) -> HTTPException:
    """
    Build the 429 that tells the caller when to retry.

    Args:
        wait (int): The seconds the caller must wait.
        what (str): What failed too often, for the message.

    Returns:
        HTTPException: A 429 with ``Retry-After``.
    """
    return HTTPException(
        status.HTTP_429_TOO_MANY_REQUESTS,
        f"too many failed {what}: try again later",
        headers={"Retry-After": str(wait)},
    )


@router.post("/login", status_code=status.HTTP_204_NO_CONTENT)
def login(body: LoginIn, request: Request, response: Response, session: SessionDep) -> None:
    """Verify the credentials and set the session cookie. 401 on a mismatch, 429 after too many."""
    throttle: LoginThrottle = request.app.state.login_throttle
    client_key = _client_key(request)
    user_key = f"user:{body.username.lower()}"
    # A client already waiting does not compete for a check. The answer depends on the client
    # alone, so it is the same for every username; ``begin_login`` below still decides atomically.
    if wait := throttle.retry_after(client_key):
        raise _too_many(wait, "logins")
    with throttle.check_slot() as admitted:
        # Asked before the username is looked at, so the answer is the same for every name.
        if not admitted:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "too many logins in progress: try again shortly",
                headers={"Retry-After": str(BUSY_RETRY_S)},
            )
        # Checked and counted in one step, so parallel guesses cannot all slip through one window.
        wait = throttle.begin_login(client_key, user_key)
        if wait:
            raise _too_many(wait, "logins")
        # Before the hash is read: a change that lands during the check is then later than this
        # session's token, which it ends.
        started = utcnow()
        user = session.exec(select(User).where(User.username == body.username)).first()
        # One Argon2 check whether or not the user exists, so the response time does not say which.
        stored_hash = user.password_hash if user is not None else dummy_password_hash()
        password_ok = verify_password(body.password, stored_hash)
    if user is None or not password_ok:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid username or password")
    throttle.finish_login(client_key, user_key)
    assert user.id is not None
    config = request.app.state.config
    # Never older than the change whose hash it just verified, whatever the clock's resolution.
    issued_at = max(started, credentials_stamp(user))
    token = create_token(
        user.id, request.app.state.session_secret, config.session_ttl_hours, issued_at=issued_at
    )
    set_session_cookie(response, token, config)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(response: Response) -> None:
    """Clear the session cookie. Always succeeds, authenticated or not."""
    clear_session_cookie(response)


@router.get("/me")
def me(user: CurrentUser) -> UserOut:
    """The current user, for the UI to render the session state."""
    assert user.id is not None
    return UserOut(id=user.id, username=user.username, created_at=user.created_at)


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    body: PasswordChangeIn,
    request: Request,
    response: Response,
    user: CurrentUser,
    session: SessionDep,
) -> None:
    """
    Change the password after re-checking the current one. 403 if it is wrong, 429 after too many,
    409 if another change got there first.

    The re-check is throttled like a login: a stolen session must not become an unlimited oracle
    for the current password. Every other session is signed out; this one gets a fresh cookie and
    stays signed in.
    """
    assert user.id is not None
    user_id = user.id
    throttle: LoginThrottle = request.app.state.login_throttle
    key = f"password:user:{user_id}"
    wait = throttle.begin_attempt(key)
    if wait:
        raise _too_many(wait, "password checks")
    verified_hash = user.password_hash
    if not verify_password(body.current_password, verified_hash):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "current password is incorrect")
    throttle.clear(key)
    changed_at = store_password_hash(
        session, user_id, hash_password(body.new_password), expected_hash=verified_hash
    )
    if changed_at is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "the password was changed by another request")
    config = request.app.state.config
    # Issued at the very moment stored as the change, so this cookie is never older than it.
    token = create_token(
        user_id, request.app.state.session_secret, config.session_ttl_hours, issued_at=changed_at
    )
    set_session_cookie(response, token, config)
