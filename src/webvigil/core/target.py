"""
Target parsing, URL normalization, and scope checks.

A :class:`Target` is built once at the start of a scan and shared (read-only)
with the HTTP layer, the crawler, and every check.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit, urlunsplit

from webvigil.core.errors import InvalidTargetError

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_DEFAULT_PORTS = {"http": 80, "https": 443}

# A hostname is an IPv4 literal, dotted DNS labels, or a single label: the name a Compose file, a
# cluster or an intranet gives a service (``app``, ``wiki``); ``localhost`` is one of them.
_HOSTNAME_RE = re.compile(
    r"^(?:(?:\d{1,3}\.){3}\d{1,3}"
    r"|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}"
    r"|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$"
)
# A leading "<scheme>:" that is not http(s) and has no "//" (e.g. "mailto:a@b.c").
_BARE_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*:(?!//)", re.IGNORECASE)

# A tiny multi-label public-suffix subset, enough for the common cases that matter for
# ``--scope subdomains``. Anything not listed falls back to "last two labels", which is
# documented as a limitation (see design ADR / Risks). Ordered longest-first at match time.
_MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "gov.uk",
        "ac.uk",
        "com.br",
        "com.au",
        "co.jp",
        "co.nz",
        "co.za",
        "com.mx",
        "github.io",
    }
)


class Scope(StrEnum):
    """
    How wide the scan is allowed to reach.

    Attributes:
        HOST (str): Only the exact target host.
        SUBDOMAINS (str): The target's registrable domain and any subdomain.
    """

    HOST = "host"
    SUBDOMAINS = "subdomains"


def is_valid_host(host: str) -> bool:
    """
    Whether ``host`` is something a scan may target.

    Args:
        host (str): A lower-cased host as ``urlsplit(...).hostname`` returns it (an IPv6 literal
            comes without its brackets).

    Returns:
        bool: ``True`` for an IPv4 literal, an IPv6 literal (without a zone id), dotted DNS labels
            or a single label. An all-digit single label is refused: a browser reads it as a
            shorthand IPv4 address, and a scan should not guess which.
    """
    if ":" in host:
        if "%" in host:
            return False
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return False
        return True
    if not _HOSTNAME_RE.match(host):
        return False
    return "." in host or not host.isdigit()


def _is_domain_name(host: str) -> bool:
    """
    Args:
        host (str): A lower-cased host.

    Returns:
        bool: ``True`` when ``host`` is a dotted DNS name, so a registrable domain can be taken
            from it; ``False`` for a one-label name and for an IPv4 or IPv6 literal.
    """
    return "." in host and ":" not in host and not host.replace(".", "").isdigit()


def url_host(host: str) -> str:
    """
    Args:
        host (str): A host as :attr:`Target.host` holds it.

    Returns:
        str: The form that goes inside a URL: an IPv6 literal gets its brackets, anything else is
            unchanged.
    """
    return f"[{host}]" if ":" in host else host


def normalize_url(url: str) -> str:
    """
    Return a canonical form of ``url`` for de-duplication and comparison.

    Lowercases the scheme and host, drops a default port, drops the fragment,
    and keeps the path (at least ``/``) and query.

    Args:
        url (str): An absolute URL. A value with no host is returned unchanged.

    Returns:
        str: The canonical URL.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not host:
        return url
    netloc = url_host(host)
    if parts.port is not None and parts.port != _DEFAULT_PORTS.get(scheme):
        netloc = f"{netloc}:{parts.port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def registrable_domain(host: str) -> str:
    """
    Best-effort registrable domain of ``host`` using the bundled suffix subset.

    Args:
        host (str): A hostname, e.g. ``"api.example.co.uk"``.

    Returns:
        str: The registrable domain (``"example.co.uk"``). Falls back to the
            last two labels for any suffix not in ``_MULTI_LABEL_SUFFIXES``.
    """
    labels = host.lower().split(".")
    if len(labels) <= 2:
        return host.lower()
    last_two = ".".join(labels[-2:])
    last_three = ".".join(labels[-3:])
    if last_two in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return last_three
    return last_two


@dataclass(frozen=True, slots=True)
class Target:
    """
    A normalized scan target plus its scope rule.

    Attributes:
        entry_url (str): The normalized URL the scan starts from.
        host (str): The lower-cased target host; an IPv6 literal is held without its brackets
            (use :func:`url_host` to put it in a URL).
        origin (str): Scheme + host + non-default port, with no path or query.
        scope (Scope): How wide the crawl may reach.
    """

    entry_url: str
    host: str
    origin: str
    scope: Scope

    @classmethod
    def parse(cls, raw: str, *, scope: Scope = Scope.HOST) -> Target:
        """
        Build a target from user input, assuming ``https://`` when no scheme is given.

        Args:
            raw (str): The target as typed by the user.
            scope (Scope): How wide the crawl may reach. Defaults to
                :attr:`Scope.HOST`.

        Returns:
            Target: The parsed, normalized target.

        Raises:
            InvalidTargetError: If ``raw`` is empty, carries a non-HTTP scheme,
                or has no usable host (see :func:`is_valid_host`).
        """
        candidate = raw.strip()
        if not candidate:
            raise InvalidTargetError("target URL is empty")
        if "://" not in candidate:
            if _BARE_SCHEME_RE.match(candidate):
                raise InvalidTargetError(f"unsupported target: {raw!r} (want an http/https URL)")
            candidate = f"https://{candidate}"

        try:
            parts = urlsplit(candidate)
            hostname = parts.hostname  # a malformed bracketed host raises here
        except ValueError:
            raise InvalidTargetError(f"could not determine a valid host from {raw!r}") from None
        if parts.scheme.lower() not in _ALLOWED_SCHEMES:
            raise InvalidTargetError(f"unsupported scheme: {parts.scheme!r} (expected http/https)")
        host = (hostname or "").lower()
        if not is_valid_host(host):
            raise InvalidTargetError(f"could not determine a valid host from {raw!r}")

        scheme = parts.scheme.lower()
        origin_netloc = url_host(host)
        if parts.port is not None and parts.port != _DEFAULT_PORTS.get(scheme):
            origin_netloc = f"{origin_netloc}:{parts.port}"

        entry_url = normalize_url(candidate)
        origin = urlunsplit((scheme, origin_netloc, "", "", ""))
        return cls(entry_url=entry_url, host=host, origin=origin, scope=scope)

    def in_scope(self, url: str) -> bool:
        """
        Whether ``url`` may be requested under this target's scope rule.

        Args:
            url (str): An absolute URL, or a bare ``host[:port]``.

        Returns:
            bool: ``True`` when the host equals the target host, or — under
                :attr:`Scope.SUBDOMAINS` and a dotted name — shares its registrable domain.
        """
        parts = urlsplit(url if "://" in url else f"//{url}")
        other = (parts.hostname or "").lower()
        if not other:
            return False
        if other == self.host:
            return True
        # A one-label name (``app``) or an IP literal has no registrable domain: widening it would
        # let ``evil.app`` in, so it stays an exact match, as under ``Scope.HOST`` (issue #191).
        if self.scope is Scope.SUBDOMAINS and _is_domain_name(self.host):
            base = registrable_domain(self.host)
            return other == base or other.endswith(f".{base}")
        return False
