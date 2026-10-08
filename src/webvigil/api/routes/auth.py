"""
Login, logout, session identity, and password change (RF-02..RF-06).
"""

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


@router.post("/login", status_code=status.HTTP_204_NO_CONTENT)
def login(body: LoginIn, request: Request, response: Response, session: SessionDep) -> None:
    """Verify the credentials and set the session cookie. 401 on a mismatch, 429 after too many."""
    throttle: LoginThrottle = request.app.state.login_throttle
    client = request.client.host if request.client else "unknown"
    keys = (f"client:{client}", f"user:{body.username.lower()}")
    wait = throttle.retry_after(*keys)
    if wait:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many failed logins: try again later",
            headers={"Retry-After": str(wait)},
        )
    user = session.exec(select(User).where(User.username == body.username)).first()
    # One Argon2 check whether or not the user exists, so the response time does not say which.
    stored_hash = user.password_hash if user is not None else dummy_password_hash()
    password_ok = verify_password(body.password, stored_hash)
    if user is None or not password_ok:
        throttle.record_failure(*keys)
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
    """Change the password after re-checking the current one. 403 if it is wrong.

    Every other session is signed out; this one gets a fresh cookie and stays signed in."""
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "current password is incorrect")
    user.password_hash = hash_password(body.new_password)
    user.updated_at = utcnow()
    session.add(user)
    session.commit()
    assert user.id is not None
    config = request.app.state.config
    token = create_token(user.id, request.app.state.session_secret, config.session_ttl_hours)
    set_session_cookie(response, token, config)
