"""
What a session cookie is, and how to read the session ids out of a response (spec 020, RF-02).

The one definition of "a session-looking cookie": the CSRF check uses it to find the weakest
``SameSite`` of a session, and the session-security pass uses it to pick the ids it judges.
A cookie is a session id by its **name**; a JWT-shaped value is skipped everywhere, because it
is a signed document and not a random identifier.
"""

from __future__ import annotations

import base64
import json
import re
from http.cookies import SimpleCookie

import httpx

SESSION_NAME_RE = re.compile(
    r"session|sess(?:id)?|sid|auth|jwt|(?:^|[_-])token|connect\.sid|phpsessid|jsessionid",
    re.I,
)
_B64URL = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


def is_session_cookie(name: str) -> bool:
    """
    Args:
        name (str): A cookie name.

    Returns:
        bool: ``True`` when the name looks like it carries a session id or an auth token.
    """
    return bool(SESSION_NAME_RE.search(name))


def is_jwt(value: str) -> bool:
    """
    Args:
        value (str): A cookie value.

    Returns:
        bool: ``True`` for three base64url segments whose first decodes to a JSON object (a
            JWT header). Not a validation of the token: only enough to skip it.
    """
    parts = value.split(".")
    if len(parts) != 3 or not all(part and _B64URL.match(part) for part in parts):
        return False
    header = parts[0]
    try:
        decoded = base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
        return isinstance(json.loads(decoded), dict)
    except (ValueError, UnicodeDecodeError):
        return False


def session_cookies(headers: httpx.Headers) -> list[tuple[str, str]]:
    """
    The session-looking cookies a response sets.

    Args:
        headers (httpx.Headers): A response's headers; every ``Set-Cookie`` line is read.

    Returns:
        list[tuple[str, str]]: ``(name, value)`` per session-looking cookie, in header order;
            JWT-shaped values and malformed lines are left out.
    """
    found: list[tuple[str, str]] = []
    for raw in headers.get_list("set-cookie"):
        jar: SimpleCookie = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:  # a malformed Set-Cookie must not break a check
            continue
        for name, morsel in jar.items():
            if is_session_cookie(name) and morsel.value and not is_jwt(morsel.value):
                found.append((name, morsel.value))
    return found


__all__ = ["SESSION_NAME_RE", "is_jwt", "is_session_cookie", "session_cookies"]
