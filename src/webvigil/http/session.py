"""
The login session: a cookie jar that holds only the session, and the "did it drop?" logic.

Spec 019. :class:`~webvigil.http.client.HttpClient` consults a :class:`Session` when one is
attached: it sends the jar's cookies on target-host requests, feeds every response back to
the jar, and when a response says the session dropped it asks :meth:`Session.recover` for a
single, serialised re-login before retrying the request once.

This module knows nothing about how a login is performed (that is
:class:`~webvigil.auth.login.Authenticator`) and imports neither the crawler nor the client:
the login URL test, the re-login and the confirmation are handed in as callables.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

import httpx2

from webvigil.core.destination import may_carry_credentials
from webvigil.core.result import LoginSummary
from webvigil.core.secrets import Secret, SecretKind

if TYPE_CHECKING:
    from webvigil.core.target import Target
    from webvigil.http.client import Response

# A login marker (``logged_in_marker``, ``logged_out_marker``) is searched in at most this much
# of the body, here and in the login (``auth.login``): a login page is small, and a regular
# expression over a multi-megabyte download is a cost nobody asked for.
MARKER_BODY_CHARS = 200_000


# ---------------------------------------------------------------------------
# The jar
# ---------------------------------------------------------------------------

_SECURE_ATTRIBUTE = re.compile(r";\s*secure\s*(?:;|$)", re.I)

# A cookie is bytes the server expects back unchanged, in whatever encoding it chose. The stdlib
# jar works on text and strips what ``str.strip`` calls whitespace, which in Latin-1 includes
# 0x85 and 0xA0 (the last byte of a UTF-8 "à"). So inside the jar each byte above 0x7F of a name
# or value is one private-use character: never whitespace, and exactly reversible.
_JAR_BYTE_OFFSET = 0xF700
_BYTES_TO_JAR = {byte: _JAR_BYTE_OFFSET + byte for byte in range(0x80, 0x100)}
_JAR_TO_BYTES = {char: byte for byte, char in _BYTES_TO_JAR.items()}


def jar_text(raw: bytes) -> str:
    """
    Args:
        raw (bytes): Cookie bytes, as they travel on the wire.

    Returns:
        str: The form the jar holds; :func:`cookie_bytes` turns it back into ``raw``.
    """
    return raw.decode("latin-1").translate(_BYTES_TO_JAR)


def cookie_bytes(text: str) -> bytes:
    """
    Args:
        text (str): Cookie text in the jar's form (:func:`jar_text`).

    Returns:
        bytes: The exact bytes to send.
    """
    return text.translate(_JAR_TO_BYTES).encode("latin-1")


def readable_cookie(text: str) -> str:
    """
    Args:
        text (str): Cookie text in the jar's form (:func:`jar_text`).

    Returns:
        str: The text for a person: UTF-8 when the bytes are valid UTF-8, else Latin-1.
    """
    raw = cookie_bytes(text)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _jar_line(raw: bytes) -> str:
    """
    Args:
        raw (bytes): One ``Set-Cookie`` value.

    Returns:
        str: The line with its ``name=value`` in the jar's form. The attributes stay readable,
            because the jar compares ``Path`` and ``Domain`` with the request URL.
    """
    pair, separator, attributes = raw.partition(b";")
    return jar_text(pair) + separator.decode() + readable_cookie(jar_text(attributes))


def _jar_view(raw: httpx2.Response) -> httpx2.Response:
    """
    The ``Set-Cookie`` lines of a response, as the jar should read them.

    A ``Secure`` cookie set over plain ``http`` is dropped (spec 020): every modern browser
    rejects it ("Leave Secure Cookies Alone"), while the stdlib jar would accept it and silently
    replace a session cookie with one that is never sent back over that same ``http``.

    Args:
        raw (httpx2.Response): A response of a request to the target host.

    Returns:
        httpx2.Response: A response that carries only those lines, in the jar's form.
    """
    lines = [_jar_line(v) for k, v in raw.headers.raw if k.lower() == b"set-cookie"]
    if raw.url.scheme != "https":
        lines = [line for line in lines if not _SECURE_ATTRIBUTE.search(line)]
    headers = [(b"set-cookie", line.encode("utf-8")) for line in lines]
    view = httpx2.Response(raw.status_code, headers=headers, request=raw.request)
    view.headers.encoding = "utf-8"
    return view


# What the target can make the jar hold. A login sets a handful of cookies, and a session
# rotates its value now and then; a target that sets hundreds, rotates without end or sets
# values of any length would grow the jar, the per-request cookie walk and the redaction of the
# report, whose cost follows the characters of the values to scrub. Past
# ``_MAX_SCRUB_VALUES`` distinct values, ``_MAX_SCRUB_CHARS`` characters of them, or one value
# longer than ``_MAX_SESSION_VALUE_CHARS`` (the size RFC 6265, 6.1, asks a browser to keep at
# least, name included, so no browser session needs more) the jar gives the session up: it is
# not sent any more, so no value goes out that the report could not be scrubbed of.
_MAX_JAR_COOKIES = 64
_MAX_VARIANTS_PER_NAME = 4
_MAX_SCRUB_VALUES = 1024
_MAX_SCRUB_CHARS = 64 * 1024
_MAX_SESSION_VALUE_CHARS = 4096


def _session_value(value: str, name: str) -> Secret:
    """
    Args:
        value (str): A cookie value the target set.
        name (str): The cookie's name, in the jar's form.

    Returns:
        Secret: The value as a ``SESSION`` secret, named after its cookie in readable text.
    """
    return Secret(value, kind=SecretKind.SESSION, name=readable_cookie(name))


def _prune(jar: httpx2.Cookies) -> None:
    """
    Keep at most ``_MAX_VARIANTS_PER_NAME`` cookies of one name and ``_MAX_JAR_COOKIES`` in all.

    Args:
        jar (httpx2.Cookies): The jar to prune, in place.
    """
    per_name: dict[str, int] = {}
    total = 0
    for cookie in list(jar.jar):
        per_name[cookie.name] = per_name.get(cookie.name, 0) + 1
        total += 1
        if per_name[cookie.name] > _MAX_VARIANTS_PER_NAME or total > _MAX_JAR_COOKIES:
            jar.jar.clear(cookie.domain, cookie.path, cookie.name)
            total -= 1


class SessionJar:
    """
    A cookie jar that only ever holds the session (spec 019, RF-07).

    Wraps :class:`httpx2.Cookies` (the stdlib ``http.cookiejar`` underneath) so Domain, Path,
    ``Secure`` and expiry are the standard rules, not a hand-rolled parser. It has two modes:

    - **Handshake**: between :meth:`begin` and :meth:`commit` every ``Set-Cookie`` of every hop
      goes into a *pending* jar, and the pending jar is what is sent on the next hop, as a
      browser would.
    - **Live**: after :meth:`commit` only a cookie whose *name* the session already holds is
      accepted (a rotation); everything else the target sets is dropped, which keeps the
      stateless contract of spec 007 for everything but the session.

    Every cookie value that ever enters the jar is remembered in :attr:`values`, so the report
    can be scrubbed of it. Everything the jar hands out is a
    :class:`~webvigil.core.secrets.Secret` (spec 024, ADR-6), except :meth:`pairs_for`, which
    builds the ``Cookie`` header inside the HTTP layer; the library's own storage holds the
    plain values, because the standard cookie rules run on it.

    Attributes:
        overflowed (bool): ``True`` once the target set more distinct values, or more of their
            characters, than the scrub list holds, or one value too long to keep; the session
            is then given up for the rest of the scan.
    """

    def __init__(self, target: Target) -> None:
        """
        Args:
            target (Target): The scan target; cookies go only where its credentials may go
                (:func:`~webvigil.core.destination.may_carry_credentials`, spec 026).
        """
        self._target = target
        self._live = httpx2.Cookies()
        self._pending: httpx2.Cookies | None = None
        self._names: frozenset[str] = frozenset()
        self._values: set[Secret] = set()
        self._chars = 0  # the characters of the distinct values in ``_values``
        self.overflowed = False

    def __repr__(self) -> str:
        """
        Returns:
            str: The target origin and the names of the committed session; never a value.
        """
        return f"SessionJar(origin={self._target.origin!r}, names={sorted(self._names)!r})"

    @property
    def values(self) -> frozenset[Secret]:
        """
        Returns:
            frozenset[Secret]: Every non-empty cookie value that entered the jar until the
                session was given up, as ``SESSION`` secrets named after their cookie; a value
                too long to keep is not among them, as it is never sent.
        """
        return frozenset(self._values)

    @property
    def names(self) -> frozenset[str]:
        """
        Returns:
            frozenset[str]: The cookie names the committed session holds.
        """
        return self._names

    def pending_items(self) -> frozenset[tuple[str, Secret]]:
        """
        Returns:
            frozenset[tuple[str, Secret]]: The ``(name, value)`` of every cookie in the pending
                jar, both in the jar's form (:func:`jar_text`) and the value as a ``SESSION``
                secret; empty outside a handshake. A rotated value counts as a new item.
        """
        if self._pending is None:
            return frozenset()
        return frozenset(
            (cookie.name, _session_value(cookie.value or "", cookie.name))
            for cookie in self._pending.jar
        )

    def begin(self) -> None:
        """Start a handshake: an empty pending jar that collects the handshake's cookies."""
        self._pending = httpx2.Cookies()

    def commit(self) -> None:
        """
        Make the pending jar the live session.

        Raises:
            RuntimeError: When no handshake is in progress.
        """
        if self._pending is None:
            raise RuntimeError("commit() without begin()")
        if self.overflowed:
            self._pending = None
            return  # the session was given up: nothing is sent any more
        self._live = self._pending
        self._names = frozenset(cookie.name for cookie in self._live.jar)
        self._pending = None

    def rollback(self) -> None:
        """Discard the pending jar; the live session, if any, is untouched."""
        self._pending = None

    def absorb(self, raw: httpx2.Response, *, handshake: bool) -> None:
        """
        Take the ``Set-Cookie`` headers of one response.

        Args:
            raw (httpx2.Response): A response of a request to the target host.
            handshake (bool): ``True`` inside a handshake (every cookie is kept, in the
                pending jar); ``False`` for a live request (only a rotation of a held name).
        """
        raw = _jar_view(raw)
        if handshake:
            if self._pending is None:
                return
            self._pending.extract_cookies(raw)
            _prune(self._pending)
            self._remember(self._pending)
            return
        if not self._names:
            return
        self._live.extract_cookies(raw)
        for cookie in list(self._live.jar):
            if cookie.name not in self._names:
                self._live.jar.clear(cookie.domain, cookie.path, cookie.name)
        _prune(self._live)
        self._remember(self._live)

    def pairs_for(self, url: str, *, handshake: bool) -> list[tuple[str, str]]:
        """
        The cookies to send to ``url``.

        Args:
            url (str): The absolute request URL.
            handshake (bool): Whether the request belongs to a handshake (reads the pending
                jar) or not (reads the live one).

        Returns:
            list[tuple[str, str]]: ``(name, value)`` pairs in the jar's form (:func:`jar_text`),
                empty once the session was given up (a re-login's handshake too), for a URL the
                scan's credentials may not reach (another host, port or scheme, but the
                ``https`` upgrade), for a URL ``httpx2`` cannot build and for a cookie the
                browser rules would not send (``Secure`` on ``http``, another path, expired).
                The values are plain: they are read from the library's storage to build the
                request's ``Cookie`` header (spec 024, ADR-6).
        """
        if self.overflowed or not may_carry_credentials(self._target, url):
            return []
        jar = self._pending if handshake and self._pending is not None else self._live
        try:
            request = httpx2.Request("GET", url)
        except httpx2.InvalidURL:
            return []  # it is never sent: the HTTP client reports it as that URL's failure
        request.headers.encoding = "utf-8"  # an all-ASCII request would refuse the jar's form
        jar.set_cookie_header(request)
        header = request.headers.get("cookie", "")
        pairs: list[tuple[str, str]] = []
        for part in header.split(";"):
            name, sep, value = part.strip().partition("=")
            if sep and name:
                pairs.append((name, value))
        return pairs

    def _remember(self, jar: httpx2.Cookies) -> None:
        """
        Args:
            jar (httpx2.Cookies): The jar that just absorbed a response; every value in it
                joins the scrub list, until the session is given up.
        """
        if self.overflowed:
            return  # nothing is sent any more (:meth:`pairs_for`), so nothing more is scrubbed
        for cookie in jar.jar:
            if cookie.value:
                # the report quotes pages, so it holds the value as text, not in the jar's form;
                # a page can show the same bytes as UTF-8 or as Latin-1
                raw = cookie_bytes(cookie.value)
                forms = {readable_cookie(cookie.value), raw.decode("latin-1")}
                if any(len(form) > _MAX_SESSION_VALUE_CHARS for form in forms):
                    self._give_up()  # before the value could be sent
                    return
                for form in forms:
                    secret = _session_value(form, cookie.name)
                    if secret not in self._values:
                        self._values.add(secret)
                        self._chars += len(form)
        if len(self._values) > _MAX_SCRUB_VALUES or self._chars > _MAX_SCRUB_CHARS:
            self._give_up()

    def _give_up(self) -> None:
        """Give the session up for the rest of the scan: nothing of it is sent any more."""
        self.overflowed = True
        self._live = httpx2.Cookies()
        self._names = frozenset()


# ---------------------------------------------------------------------------
# The session
# ---------------------------------------------------------------------------


class Session:
    """
    The state of an automated login during one scan (spec 019).

    Attributes:
        jar (SessionJar): The session cookies.
        generation (int): Bumped by every committed login, so a request that noticed a drop
            can tell whether another task already re-logged in.
        relogins (int): Re-authentications attempted so far, failed ones included.
        max_relogins (int): The cap.
        lost (bool): ``True`` once the cap was hit while the session was still dropping.
        closed (bool): ``True`` once the session was ended on purpose (the logout test):
            a dropped session is then not recovered.
        confirmed (bool): ``False`` when the first login could not be verified.
        known_login_redirects (set[str]): URLs that bounce to the login page even with a
            fresh session (an app that sends unauthorised users there): never a drop signal.
    """

    def __init__(
        self,
        *,
        jar: SessionJar,
        is_login_url: Callable[[str], bool],
        logged_out_marker: str | None = None,
        max_relogins: int = 3,
        relogin: Callable[[], Awaitable[bool]] | None = None,
        confirm_dropped: Callable[[], Awaitable[bool]] | None = None,
    ) -> None:
        """
        Args:
            jar (SessionJar): The session cookies.
            is_login_url (Callable[[str], bool]): Whether a URL is the login page.
            logged_out_marker (str | None): Regular expression that matches the body of a
                logged-out page. Defaults to ``None``.
            max_relogins (int): Re-authentications allowed. Defaults to 3.
            relogin (Callable[[], Awaitable[bool]] | None): Performs one re-login and returns
                whether it was committed. ``None`` disables recovery.
            confirm_dropped (Callable[[], Awaitable[bool]] | None): Fetches the configured
                ``check_url`` and returns whether it looks logged out. ``None`` skips the
                confirmation. Defaults to ``None``.
        """
        self.jar = jar
        self.generation = 0
        self.relogins = 0
        self.max_relogins = max_relogins
        self.lost = False
        self.confirmed = True
        self.closed = False
        self.known_login_redirects: set[str] = set()
        self.failed_relogins = 0
        self._failures: list[str] = []
        self._is_login_url = is_login_url
        self._marker = re.compile(logged_out_marker) if logged_out_marker else None
        self._relogin = relogin
        self._confirm = confirm_dropped
        self._lock = asyncio.Lock()

    def __repr__(self) -> str:
        """
        Returns:
            str: The jar's names-only form and the session's counters; never a value.
        """
        return (
            f"Session(jar={self.jar!r}, generation={self.generation}, "
            f"relogins={self.relogins}, lost={self.lost}, closed={self.closed})"
        )

    @property
    def secrets(self) -> frozenset[Secret]:
        """
        Returns:
            frozenset[Secret]: Every session cookie value the jar ever held. They are the
                target's, so the scrub removes them only when they look like a session id
                (``webvigil.auth.scrub.looks_like_session_value``); the password reaches it from
                the credentials (spec 024, RF-07).
        """
        return self.jar.values

    def looks_dropped(self, response: Response) -> bool:
        """
        Whether a response to a target-host request says the session is gone (RF-08).

        A ``403``, a ``5xx`` and a redirect that leaves the scope are never a drop: an
        injection payload that draws a block page must not trigger a re-login.

        Args:
            response (Response): The final response of a request.

        Returns:
            bool: ``True`` for a ``401``, a redirect to the login page from a page that is not
                itself a login page, or a body that matches ``logged_out_marker`` -- unless
                the requested URL is a known bouncer (a page that answers that way even with
                a fresh session, learned once: ADR-6).
        """
        if response.requested_url in self.known_login_redirects:
            return False
        if response.status_code == 401:
            return True
        if (
            response.history
            and self._is_login_url(response.url)
            and not self._is_login_url(response.requested_url)
        ):
            return True
        return self._marker is not None and bool(
            self._marker.search(response.text[:MARKER_BODY_CHARS])
        )

    def learn(self, url: str) -> None:
        """
        Remember that ``url`` answers like a dropped session even with a fresh one.

        Args:
            url (str): The requested URL.
        """
        self.known_login_redirects.add(url)

    async def recover(self, seen: int, url: str) -> bool:
        """
        Re-authenticate once, however many requests noticed the drop (RF-09).

        Args:
            seen (int): The :attr:`generation` the request was sent under.
            url (str): The requested URL that signalled the drop.

        Returns:
            bool: ``True`` when the request should be retried with the (new) session;
                ``False`` when it should not (the cap was reached, the ``check_url`` says the
                session is fine, or the re-login failed).
        """
        async with self._lock:
            if self.generation != seen:
                return True  # another task re-logged in while this one waited
            if self._relogin is None or self.closed:
                return False
            if self.relogins >= self.max_relogins:
                self.lost = True
                return False
            if self._confirm is not None and not await self._confirm():
                self.learn(url)  # the login redirect is this page's own behaviour
                return False
            self.relogins += 1  # a failed attempt costs one too
            ok = await self._relogin()
            if not ok:
                self.failed_relogins += 1
            return ok

    def note_failure(self, message: str) -> None:
        """
        Record why a re-login failed, for the scan warnings.

        Args:
            message (str): The failure message; it never carries a secret.
        """
        self._failures.append(message)

    def close(self) -> None:
        """Mark the session ended on purpose (the logout test, spec 020): no re-login follows."""
        self.closed = True

    def committed(self) -> None:
        """Record a committed (re)login: a new generation."""
        self.generation += 1

    def summary(self) -> LoginSummary:
        """
        Returns:
            LoginSummary: The facts for the scan metadata.
        """
        return LoginSummary(
            relogins=self.relogins,
            session_lost=self.lost or self.jar.overflowed,
            confirmed=self.confirmed,
        )

    def warnings(self) -> list[str]:
        """
        Returns:
            list[str]: The scan warnings the session earned: an unconfirmed login, failed
                re-logins, a session lost for the rest of the scan. Never a secret.
        """
        lines: list[str] = []
        if not self.confirmed:
            lines.append(
                "the login could not be confirmed (no marker, no check_url, and the page "
                "gave no clear answer) - the scan continued"
            )
        if self.failed_relogins:
            reason = f": {self._failures[-1]}" if self._failures else ""
            lines.append(f"{self.failed_relogins} re-login attempt(s) failed{reason}")
        if self.lost:
            lines.append(
                f"the session was lost after {self.relogins} re-login(s) - the rest of the "
                "scan ran without it"
            )
        if self.jar.overflowed:
            lines.append(
                "the target changed the session cookies too many times or set one too long to "
                "keep - the rest of the scan ran without the session"
            )
        return lines


__all__ = ["Session", "SessionJar", "cookie_bytes", "jar_text", "readable_cookie"]
