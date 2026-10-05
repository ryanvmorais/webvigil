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
    """
    Args:
        request (Request): The current request.

    Returns:
        Engine: The process-wide DB engine, stored on ``app.state`` by the
            lifespan.
    """
    engine: Engine = request.app.state.engine
    return engine


def get_session(request: Request) -> Iterator[Session]:
    """
    Args:
        request (Request): The current request.

    Yields:
        Session: A request-scoped session, closed when the request ends.
    """
    with Session(request.app.state.engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


def optional_user(request: Request, session: SessionDep) -> User | None:
    """
    Resolve the user from the session cookie, or ``None`` when there is none.

    For the one endpoint that has to answer "am I signed in?" without turning
    the answer into a 401 (a 401 shows up as a console error in the browser).

    Args:
        request (Request): The current request; the session cookie is read
            here.
        session (SessionDep): The request-scoped session.

    Returns:
        User | None: The authenticated user, or ``None`` when the cookie is
            absent, invalid, expired, or names a user that no longer exists.
    """
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    user_id = decode_token(token, request.app.state.session_secret)
    if user_id is None:
        return None
    return session.get(User, user_id)


OptionalUser = Annotated[User | None, Depends(optional_user)]


def current_user(user: OptionalUser) -> User:
    """
    Require an authenticated user.

    Args:
        user (OptionalUser): The user resolved from the session cookie, if any.

    Returns:
        User: The authenticated user.

    Raises:
        HTTPException: 401 when there is no valid session (see
            :func:`optional_user` for what counts as one).
    """
    if user is None:
        raise _UNAUTHENTICATED
    return user


CurrentUser = Annotated[User, Depends(current_user)]


def get_runner(request: Request) -> ScanRunner:
    """
    Args:
        request (Request): The current request.

    Returns:
        ScanRunner: The process-wide scan runner, stored on ``app.state`` by
            the lifespan.
    """
    runner: ScanRunner = request.app.state.runner
    return runner


RunnerDep = Annotated[ScanRunner, Depends(get_runner)]
