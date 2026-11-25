"""
The destination policy: the one place that decides what each URL may receive (spec 026).

Every part of the engine that sends a request, keeps a cookie or follows a redirect asks these
functions, never :class:`~webvigil.core.target.Target` directly:

* :func:`may_request`: the URL may be requested at all (the scope rule).
* :func:`may_carry_credentials`: the scan's credentials may go to the URL, and a ``Set-Cookie``
  from it may be kept (the credential rule).
* :func:`keeps_data`: a redirect may replay a request's body and query to the next URL.
* :func:`without_credentials`: a caller's headers, without the credentials the URL may not get.
* :func:`is_target_host`: the URL names the target host; it only chooses a message.
* :func:`is_public_name`: a host is a name on the public internet, for the address notices.

The two rules themselves stay in ``Target`` (``in_scope`` and ``carries_credentials``), and this
module is the only code in the package that calls them, so two callers that ask about the same URL
get the same answer by construction. The functions hold no state.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from webvigil.core.suffixes import load_rules

if TYPE_CHECKING:
    from webvigil.core.target import Target

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


# The headers that carry a credential whatever the scan configures: the session and static
# cookies, and a bearer or basic ``Authorization``. A configured ``[auth]`` header name is added to
# them per call (see :func:`without_credentials`).
CREDENTIAL_HEADERS = frozenset({"cookie", "authorization"})

# Top-level labels that never name a site on the internet, though some are on the Public Suffix
# List (``arpa``, ``onion``): the IANA special-use names (RFC 6761, 6762, 7686, 8375, 9476) and
# ``internal``, which ICANN reserved for private use.
SPECIAL_USE_LABELS = frozenset(
    {"alt", "arpa", "example", "internal", "invalid", "local", "localhost", "onion", "test"}
)


# ---------------------------------------------------------------------------
# The scope and credential rules
# ---------------------------------------------------------------------------


def may_request(target: Target, url: str) -> bool:
    """
    Args:
        target (Target): The scan target.
        url (str): An absolute URL, or a bare ``host[:port]``.

    Returns:
        bool: ``True`` when the scan may send a request to ``url`` (the target's scope rule).
    """
    return target.in_scope(url)


def may_carry_credentials(target: Target, url: str) -> bool:
    """
    Whether the scan's credentials may go to ``url``, and a ``Set-Cookie`` from it may be kept.

    The configured ``[auth]`` cookies and headers, the session of the automated login and its
    password go to the target origin only, or to its ``https`` upgrade.

    Args:
        target (Target): The scan target.
        url (str): An absolute URL.

    Returns:
        bool: ``True`` for the target's scheme, host and port, and for ``https`` on port 443 when
            the target is ``http`` on port 80.
    """
    return target.carries_credentials(url)


# ---------------------------------------------------------------------------
# Redirects and caller headers
# ---------------------------------------------------------------------------


def keeps_data(target: Target, current_url: str, next_url: str, *, credentialed: bool) -> bool:
    """
    Whether a redirect from ``current_url`` may replay its body and query to ``next_url``.

    Headers can be filtered hop by hop, a request's data cannot: a body or query sent with the
    scan's credentials can hold what they unlocked (the login's password, an anti-CSRF token). So
    such data stays off a URL that may not carry the credentials. A request that carried none has
    nothing of them to protect.

    Args:
        target (Target): The scan target.
        current_url (str): The URL that answered with the redirect.
        next_url (str): The URL the redirect points to.
        credentialed (bool): The request went out with the scan's credentials (the scan holds a
            session, a static cookie or an ``[auth]`` header, and the request is not anonymous).

    Returns:
        bool: ``False`` only when the request was credentialed, ``current_url`` may carry the
            credentials and ``next_url`` may not.
    """
    if not credentialed:
        return True
    return not (
        may_carry_credentials(target, current_url) and not may_carry_credentials(target, next_url)
    )


def without_credentials(
    target: Target, headers: Mapping[str, str] | None, url: str, *, auth_names: Iterable[str]
) -> dict[str, str] | None:
    """
    A caller's headers for ``url``, without the credentials ``url`` may not get.

    A caller can pass a credential itself (the session tests send the login's cookies as a
    ``Cookie`` header). Where :func:`may_carry_credentials` says no, a ``Cookie``, an
    ``Authorization`` and every configured ``[auth]`` header name is dropped, compared without
    regard to case, as the client never adds its own there.

    Args:
        target (Target): The scan target.
        headers (Mapping[str, str] | None): The headers the caller passed.
        url (str): The URL the request goes to.
        auth_names (Iterable[str]): The header names the scan's ``[auth]`` section configures.

    Returns:
        dict[str, str] | None: ``None`` for ``None``; a copy of ``headers`` with every entry when
            ``url`` may carry the credentials; otherwise a copy without the credential headers.
    """
    if headers is None:
        return None
    if may_carry_credentials(target, url):
        return dict(headers)
    secret = CREDENTIAL_HEADERS | {name.lower() for name in auth_names}
    return {name: value for name, value in headers.items() if name.lower() not in secret}


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------


def is_target_host(target: Target, url: str) -> bool:
    """
    Whether ``url`` names the target host, whatever its scheme and port.

    It chooses a message (the delegated-login message, the OpenAPI server warning) and never
    decides what is sent: that is :func:`may_request` and :func:`may_carry_credentials`.

    Args:
        target (Target): The scan target.
        url (str): An absolute URL.

    Returns:
        bool: ``True`` when the URL's host (``urlsplit`` lower-cases it) equals ``target.host``;
            ``False`` for a URL with no host or a malformed one.
    """
    try:
        return urlsplit(url).hostname == target.host
    except ValueError:
        return False


def is_public_name(host: str) -> bool:
    """
    Whether ``host`` is a DNS name on the public internet.

    A public name is dotted (not one label, not an IP literal), and its top-level label is a rule
    of the vendored Public Suffix List (an exact rule, or the base of a wildcard rule) that is not
    in :data:`SPECIAL_USE_LABELS`. A registrable domain is not enough: the list's default rule
    gives one to ``app.local`` and ``svc.cluster.local`` too.

    Args:
        host (str): A host as ``urlsplit(...).hostname`` returns it; a trailing dot is ignored.

    Returns:
        bool: ``True`` for ``app.example.com`` or ``x.y.ck``; ``False`` for ``app.local``,
            ``x.onion``, ``localhost``, ``app`` or ``10.0.0.5``.
    """
    name = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        return False
    labels = name.split(".")
    if len(labels) < 2 or not all(labels):
        return False
    top = labels[-1]
    if top in SPECIAL_USE_LABELS:
        return False
    rules = load_rules()
    return top in rules.exact or top in rules.wildcards


__all__ = [
    "CREDENTIAL_HEADERS",
    "SPECIAL_USE_LABELS",
    "is_public_name",
    "is_target_host",
    "keeps_data",
    "may_carry_credentials",
    "may_request",
    "without_credentials",
]
