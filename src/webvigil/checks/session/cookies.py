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
# What a browser keeps of a ``Set-Cookie`` line (RFC 6265bis, draft 22): a cookie whose name and
# value together pass 4096 octets is ignored whole (section 5.7), and an attribute whose value
# passes 1024 octets is ignored alone (section 5.6). The checks read no more than that, so the
# standard library's parser, whose cost on Python 3.12 before 3.12.6 grows quadratically with the
# backslashes of a quoted value (CVE-2024-7592), never gets a longer one.
MAX_NAME_VALUE_OCTETS = 4096
MAX_ATTRIBUTE_VALUE_OCTETS = 1024


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
    except (ValueError, UnicodeDecodeError, RecursionError):
        return False


def _octets(text: str) -> int:
    """
    Args:
        text (str): A header value, or part of one.

    Returns:
        int: Its length in UTF-8 octets.
    """
    return len(text.encode("utf-8", "replace"))


def cookie_pair(raw: str) -> str | None:
    """
    Take the ``name=value`` pair of one ``Set-Cookie`` line, as a browser would keep it.

    Args:
        raw (str): One raw ``Set-Cookie`` header value.

    Returns:
        str | None: The text before the first ``;``, or ``None`` when its name and value pass
            ``MAX_NAME_VALUE_OCTETS`` together (a browser ignores that cookie).
    """
    pair = raw.partition(";")[0]
    name, _, value = pair.partition("=")
    if _octets(name.strip()) + _octets(value.strip()) > MAX_NAME_VALUE_OCTETS:
        return None
    return pair


def cookie_attribute(raw: str, name: str) -> str | None:
    """
    Read one attribute of a ``Set-Cookie`` line, as a browser would.

    The line is split at ``;``, in time proportional to it; the last attribute with the name
    wins, and one whose value passes ``MAX_ATTRIBUTE_VALUE_OCTETS`` is ignored.

    Args:
        raw (str): One raw ``Set-Cookie`` header value.
        name (str): The attribute name, matched case-insensitively.

    Returns:
        str | None: The attribute's value (``""`` for a flag), or ``None`` when absent.
    """
    found: str | None = None
    for attribute in raw.split(";")[1:]:
        key, _, value = attribute.partition("=")
        if key.strip().lower() != name.lower():
            continue
        value = value.strip()
        if _octets(value) <= MAX_ATTRIBUTE_VALUE_OCTETS:
            found = value
    return found


def session_cookies(headers: httpx.Headers) -> list[tuple[str, str]]:
    """
    The session-looking cookies a response sets.

    Args:
        headers (httpx.Headers): A response's headers; every ``Set-Cookie`` line is read.

    Returns:
        list[tuple[str, str]]: ``(name, value)`` per session-looking cookie, in header order;
            JWT-shaped values, malformed lines and cookies a browser ignores (see
            :func:`cookie_pair`) are left out. Only the ``name=value`` pair is parsed.
    """
    found: list[tuple[str, str]] = []
    for raw in headers.get_list("set-cookie"):
        pair = cookie_pair(raw)
        if pair is None:
            continue
        jar: SimpleCookie = SimpleCookie()
        try:
            jar.load(pair)
        except Exception:  # a malformed Set-Cookie must not break a check
            continue
        for name, morsel in jar.items():
            if is_session_cookie(name) and morsel.value and not is_jwt(morsel.value):
                found.append((name, morsel.value))
    return found


__all__ = [
    "MAX_ATTRIBUTE_VALUE_OCTETS",
    "MAX_NAME_VALUE_OCTETS",
    "SESSION_NAME_RE",
    "cookie_attribute",
    "cookie_pair",
    "is_jwt",
    "is_session_cookie",
    "session_cookies",
]
