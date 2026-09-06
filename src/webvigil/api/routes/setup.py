"""First-run account creation (RF-01)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func
from sqlmodel import select

from webvigil.api.db import User
from webvigil.api.deps import SessionDep
from webvigil.api.schemas import SetupIn, UserOut
from webvigil.api.security import hash_password

router = APIRouter(tags=["setup"])


def _user_count(session: SessionDep) -> int:
    return session.exec(select(func.count()).select_from(User)).one()


@router.get("/setup")
def setup_status(session: SessionDep) -> dict[str, bool]:
    return {"needs_setup": _user_count(session) == 0}


@router.post("/setup", status_code=status.HTTP_201_CREATED)
def create_first_user(body: SetupIn, session: SessionDep) -> UserOut:
    if _user_count(session) > 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "setup has already been completed")
    user = User(username=body.username, password_hash=hash_password(body.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    assert user.id is not None
    return UserOut(id=user.id, username=user.username, created_at=user.created_at)
