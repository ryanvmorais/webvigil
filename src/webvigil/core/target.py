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
from webvigil.core.suffixes import load_rules

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


def registrable_domain(host: str) -> str | None:
    """
    Registrable domain of ``host`` by the vendored Public Suffix List (:mod:`.suffixes`).

    Args:
        host (str): A hostname in ASCII, e.g. ``"api.example.co.uk"``.

    Returns:
        str | None: The registrable domain (``"example.co.uk"``; ``"alice.github.io"`` for
            ``"www.alice.github.io"``, since ``github.io`` is a public suffix), or ``None`` when
            ``host`` is itself a public suffix.
    """
    return load_rules().registrable_domain(host)


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

    @property
    def scheme(self) -> str:
        """
        Returns:
            str: The target's scheme, ``"http"`` or ``"https"``.
        """
        return urlsplit(self.origin).scheme

    @property
    def port(self) -> int:
        """
        Returns:
            int: The target's port, the scheme's default when the URL names none.
        """
        port = urlsplit(self.origin).port
        return port if port is not None else _DEFAULT_PORTS[self.scheme]

    def _endpoint(self, url: str) -> tuple[str, str, int] | None:
        """
        Args:
            url (str): An absolute URL, or a bare ``host[:port]`` (read with the target's scheme).

        Returns:
            tuple[str, str, int] | None: The lower-cased scheme, host and port the URL reaches,
                or ``None`` when it has no host, a scheme other than ``http``/``https``, or a
                malformed port.
        """
        try:
            parts = urlsplit(url if "://" in url else f"{self.scheme}://{url}")
            host = (parts.hostname or "").lower()
            port = parts.port
        except ValueError:
            return None
        scheme = parts.scheme.lower()
        if not host or scheme not in _ALLOWED_SCHEMES:
            return None
        return scheme, host, port if port is not None else _DEFAULT_PORTS[scheme]

    def _port_in_scope(self, scheme: str, port: int) -> bool:
        """
        Args:
            scheme (str): The URL's scheme.
            port (int): The URL's port.

        Returns:
            bool: ``True`` for the target's own port and, when the target uses its scheme's
                default port, for the ``http``/``https`` pair on ports 80 and 443 (a site that
                links its other scheme). Another port is another service.
        """
        if port == self.port:
            return True
        return self.port == _DEFAULT_PORTS[self.scheme] and port == _DEFAULT_PORTS[scheme]

    def in_scope(self, url: str) -> bool:
        """
        Whether ``url`` may be requested under this target's scope rule.

        Args:
            url (str): An absolute URL, or a bare ``host[:port]``.

        Returns:
            bool: ``True`` when the URL is ``http``/``https``, its port passes
                :meth:`_port_in_scope`, and its host equals the target host or, under
                :attr:`Scope.SUBDOMAINS` and a dotted name, shares its registrable domain.
        """
        endpoint = self._endpoint(url)
        if endpoint is None:
            return False
        scheme, other, port = endpoint
        if not self._port_in_scope(scheme, port):
            return False
        if other == self.host:
            return True
        # A one-label name (``app``) or an IP literal has no registrable domain: widening it would
        # let ``evil.app`` in, so it stays an exact match, as under ``Scope.HOST`` (issue #191).
        # A target that is itself a public suffix (``github.io``) has no domain to widen to:
        # every name under it is somebody else's, so it stays an exact match too.
        if self.scope is Scope.SUBDOMAINS and _is_domain_name(self.host):
            base = registrable_domain(self.host)
            return base is not None and (other == base or other.endswith(f".{base}"))
        return False

    def carries_credentials(self, url: str) -> bool:
        """
        Whether a request to ``url`` may carry the scan's credentials.

        Configured ``[auth]`` cookies and headers, the session of the automated login and its
        password go to the target origin only, or to its ``https`` upgrade. Never to another
        port of the same host, a subdomain, or plain ``http`` when the target is ``https``.

        Args:
            url (str): An absolute URL.

        Returns:
            bool: ``True`` for the target's scheme, host and port, and for ``https`` on port 443
                when the target is ``http`` on port 80.
        """
        endpoint = self._endpoint(url)
        if endpoint is None:
            return False
        if endpoint == (self.scheme, self.host, self.port):
            return True
        return (self.scheme, self.port) == ("http", 80) and endpoint == ("https", self.host, 443)
