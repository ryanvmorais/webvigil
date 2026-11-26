"""
First-run account creation (RF-01).

The route runs on a thread pool, so two setup requests can arrive together. The check that no
account exists and the insert happen under one lock, so exactly one of them creates the account
and the other gets ``409`` (GHSA-q373-8m5q-qwww). The server runs as one process (``serve``
starts a single uvicorn worker), so a process-wide lock covers every request.

The hash takes one of the login throttle's password-check slots, so setup requests cannot run
more Argon2 checks at once than logins can (spec 027, RF-08).
"""

from __future__ import annotations

import threading

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import func
from sqlmodel import select

from webvigil.api.db import User
from webvigil.api.deps import OptionalUser, SessionDep
from webvigil.api.schemas import SetupIn, SetupStatusOut, UserOut
from webvigil.api.security import hash_password
from webvigil.api.throttle import BUSY_RETRY_S, LoginThrottle

router = APIRouter(tags=["setup"])
_SETUP_LOCK = threading.Lock()


def _user_count(session: SessionDep) -> int:
    """
    Args:
        session (SessionDep): The request-scoped session.

    Returns:
        int: The number of rows in the ``user`` table (0 before first-run
            setup, 1 after).
    """
    return session.exec(select(func.count()).select_from(User)).one()


@router.get("/setup")
def setup_status(session: SessionDep, user: OptionalUser) -> SetupStatusOut:
    """
    Whether first-run setup is still needed and whether the caller is signed in.

    Unauthenticated: the UI checks it on load, and a missing session is
    ``authenticated: false``, never a 401.
    """
    return SetupStatusOut(needs_setup=_user_count(session) == 0, authenticated=user is not None)


@router.post("/setup", status_code=status.HTTP_201_CREATED)
def create_first_user(body: SetupIn, request: Request, session: SessionDep) -> UserOut:
    """
    Create the single account. Unauthenticated, but 409s once an account exists, and 429s
    while every password-check slot is taken.
    """
    if _user_count(session) > 0:  # the common answer, before paying for an Argon2 hash
        raise HTTPException(status.HTTP_409_CONFLICT, "setup has already been completed")
    throttle: LoginThrottle = request.app.state.login_throttle
    with throttle.check_slot() as admitted:
        if not admitted:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "too many password checks in progress: try again shortly",
                headers={"Retry-After": str(BUSY_RETRY_S)},
            )
        password_hash = hash_password(body.password)  # the slow part, outside the lock
    with _SETUP_LOCK:  # checked again: another request may have created it meanwhile
        if _user_count(session) > 0:
            raise HTTPException(status.HTTP_409_CONFLICT, "setup has already been completed")
        user = User(username=body.username, password_hash=password_hash)
        session.add(user)
        session.commit()
    session.refresh(user)
    assert user.id is not None
    return UserOut(id=user.id, username=user.username, created_at=user.created_at)
