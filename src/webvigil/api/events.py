"""
The security event log of the Web API: every sign-in, password change and setup attempt.

Each attempt, accepted or refused, is one line on the ``webvigil.api.events`` logger: the event,
the username the request named and the client address the login throttle keys on. A password
never enters a line. The username is the client's own text, so it is quoted with :func:`repr`,
which keeps a name with spaces or an ``=`` from passing for another field; the logger's filter
then gives the line the ``LOG`` profile (spec 025). An accepted attempt is ``INFO``, a refused one
``WARNING``. ``webvigil-web serve`` writes the logger to standard error with uvicorn's own lines.
"""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import Final

from webvigil.core.output import get_logger

EVENTS_LOGGER: Final = "webvigil.api.events"
_logger = get_logger(EVENTS_LOGGER)


class AuthEvent(StrEnum):
    """
    What an authentication request ended in.

    Attributes:
        LOGIN_SUCCEEDED (str): The credentials matched; a session cookie was set.
        LOGIN_FAILED (str): A wrong password or an unknown username (``401``).
        LOGIN_THROTTLED (str): Refused while the client or the username waits (``429``).
        LOGIN_BUSY (str): Refused because every password check was taken (``429``).
        PASSWORD_CHANGED (str): The current password matched and the new one is stored.
        PASSWORD_CHANGE_FAILED (str): The current password did not match (``403``).
        PASSWORD_CHANGE_THROTTLED (str): Refused while the user's checks wait (``429``).
        PASSWORD_CHANGE_CONFLICT (str): Another change was stored first (``409``).
        SETUP_SUCCEEDED (str): The first account was created.
        SETUP_REFUSED (str): An account already exists (``409``).
        SETUP_BUSY (str): Refused because every password check was taken (``429``).
    """

    LOGIN_SUCCEEDED = "login.succeeded"
    LOGIN_FAILED = "login.failed"
    LOGIN_THROTTLED = "login.throttled"
    LOGIN_BUSY = "login.busy"
    PASSWORD_CHANGED = "password_change.succeeded"
    PASSWORD_CHANGE_FAILED = "password_change.failed"
    PASSWORD_CHANGE_THROTTLED = "password_change.throttled"
    PASSWORD_CHANGE_CONFLICT = "password_change.conflict"
    SETUP_SUCCEEDED = "setup.succeeded"
    SETUP_REFUSED = "setup.refused"
    SETUP_BUSY = "setup.busy"


# The outcomes that are routine: logged at INFO, so an operator filtering on WARNING sees only the
# refusals, the ones a guess or an attack produces.
_ACCEPTED: Final = frozenset(
    {AuthEvent.LOGIN_SUCCEEDED, AuthEvent.PASSWORD_CHANGED, AuthEvent.SETUP_SUCCEEDED}
)


def record(event: AuthEvent, *, username: str, client: str) -> None:
    """
    Write one authentication attempt to the security event log.

    Args:
        event (AuthEvent): What the attempt ended in.
        username (str): The username the request named, or the signed-in user's.
        client (str): The client's address, as the login throttle reads it.
    """
    level = logging.INFO if event in _ACCEPTED else logging.WARNING
    _logger.log(level, "auth event=%s user=%r client=%s", event.value, username, client)
