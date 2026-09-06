"""FastAPI dependencies: the DB engine, a request-scoped session, and the current user."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import Engine
from sqlmodel import Session

from webvigil.api.db import User
from webvigil.api.runner import ScanRunner
from webvigil.api.security import SESSION_COOKIE, decode_token

_UNAUTHENTICATED = HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")


def get_engine(request: Request) -> Engine:
    engine: Engine = request.app.state.engine
    return engine


def get_session(request: Request) -> Iterator[Session]:
    with Session(request.app.state.engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


def current_user(request: Request, session: SessionDep) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise _UNAUTHENTICATED
    user_id = decode_token(token, request.app.state.session_secret)
    if user_id is None:
        raise _UNAUTHENTICATED
    user = session.get(User, user_id)
    if user is None:
        raise _UNAUTHENTICATED
    return user


CurrentUser = Annotated[User, Depends(current_user)]


def get_runner(request: Request) -> ScanRunner:
    runner: ScanRunner = request.app.state.runner
    return runner


RunnerDep = Annotated[ScanRunner, Depends(get_runner)]
