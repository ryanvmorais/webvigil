"""First-run account creation (RF-01)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func
from sqlmodel import select

from webvigil.api.db import User
from webvigil.api.deps import OptionalUser, SessionDep
from webvigil.api.schemas import SetupIn, SetupStatusOut, UserOut
from webvigil.api.security import hash_password

router = APIRouter(tags=["setup"])


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
def create_first_user(body: SetupIn, session: SessionDep) -> UserOut:
    """Create the single account. Unauthenticated, but 409s once an account exists."""
    if _user_count(session) > 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "setup has already been completed")
    user = User(username=body.username, password_hash=hash_password(body.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    assert user.id is not None
    return UserOut(id=user.id, username=user.username, created_at=user.created_at)
