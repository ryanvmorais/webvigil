"""Login, logout, session identity, and password change (RF-02..RF-06)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlmodel import select

from webvigil.api.db import User, utcnow
from webvigil.api.deps import CurrentUser, SessionDep
from webvigil.api.schemas import LoginIn, PasswordChangeIn, UserOut
from webvigil.api.security import (
    clear_session_cookie,
    create_token,
    dummy_password_hash,
    hash_password,
    set_session_cookie,
    verify_password,
)
from webvigil.api.throttle import LoginThrottle

router = APIRouter(prefix="/auth", tags=["auth"])


def _login_keys(request: Request, username: str) -> tuple[str, ...]:
    """
    The throttle keys a login attempt counts against.

    Behind the dashboard's proxy every request has the proxy's address, so a per-address key would
    be one key for everybody: a stranger's failures would make the owner wait too. A request the
    proxy forwarded (it carries ``X-Forwarded-Host``) counts against the username only. A client
    that sends the header itself gains nothing over the proxy: the username key still slows it.

    Args:
        request (Request): The login request.
        username (str): The username it tries.

    Returns:
        tuple[str, ...]: ``user:<name>``, preceded by ``client:<address>`` when the request did not
            come through a proxy.
    """
    user_key = f"user:{username.lower()}"
    if "x-forwarded-host" in request.headers:
        return (user_key,)
    client = request.client.host if request.client else "unknown"
    return (f"client:{client}", user_key)


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
    keys = _login_keys(request, body.username)
    # Checked and counted in one step, so parallel guesses cannot all slip through one window.
    wait = throttle.begin_attempt(*keys)
    if wait:
        raise _too_many(wait, "logins")
    user = session.exec(select(User).where(User.username == body.username)).first()
    # One Argon2 check whether or not the user exists, so the response time does not say which.
    stored_hash = user.password_hash if user is not None else dummy_password_hash()
    password_ok = verify_password(body.password, stored_hash)
    if user is None or not password_ok:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid username or password")
    throttle.clear(*keys)
    assert user.id is not None
    config = request.app.state.config
    token = create_token(user.id, request.app.state.session_secret, config.session_ttl_hours)
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
    Change the password after re-checking the current one. 403 if it is wrong, 429 after too many.

    The re-check is throttled like a login: a stolen session must not become an unlimited oracle
    for the current password. Every other session is signed out; this one gets a fresh cookie and
    stays signed in.
    """
    assert user.id is not None
    throttle: LoginThrottle = request.app.state.login_throttle
    key = f"password:user:{user.id}"
    wait = throttle.begin_attempt(key)
    if wait:
        raise _too_many(wait, "password checks")
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "current password is incorrect")
    throttle.clear(key)
    user.password_hash = hash_password(body.new_password)
    changed_at = utcnow()
    user.updated_at = changed_at
    session.add(user)
    session.commit()
    config = request.app.state.config
    # Issued at the very moment stored as the change, so this cookie is never older than it.
    token = create_token(
        user.id, request.app.state.session_secret, config.session_ttl_hours, issued_at=changed_at
    )
    set_session_cookie(response, token, config)
