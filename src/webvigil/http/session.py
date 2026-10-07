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
from collections.abc import Awaitable, Callable, Iterable
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import httpx

from webvigil.core.result import LoginSummary

if TYPE_CHECKING:
    from webvigil.http.client import Response

# A logged-out marker is searched in at most this much of the body: a login page is small, and
# a regular expression over a multi-megabyte download is a cost nobody asked for.
_MARKER_BODY_CHARS = 200_000


# ---------------------------------------------------------------------------
# The jar
# ---------------------------------------------------------------------------


class SessionJar:
    """
    A cookie jar that only ever holds the session (spec 019, RF-07).

    Wraps :class:`httpx.Cookies` (the stdlib ``http.cookiejar`` underneath) so Domain, Path,
    ``Secure`` and expiry are the standard rules, not a hand-rolled parser. It has two modes:

    - **Handshake**: between :meth:`begin` and :meth:`commit` every ``Set-Cookie`` of every hop
      goes into a *pending* jar, and the pending jar is what is sent on the next hop, as a
      browser would.
    - **Live**: after :meth:`commit` only a cookie whose *name* the session already holds is
      accepted (a rotation); everything else the target sets is dropped, which keeps the
      stateless contract of spec 007 for everything but the session.

    Every cookie value that ever enters the jar is remembered in :attr:`values`, so the report
    can be scrubbed of it.
    """

    def __init__(self, host: str) -> None:
        """
        Args:
            host (str): The target host (lower-cased); cookies are sent to no other host.
        """
        self._host = host.lower()
        self._live = httpx.Cookies()
        self._pending: httpx.Cookies | None = None
        self._names: frozenset[str] = frozenset()
        self._values: set[str] = set()

    @property
    def values(self) -> frozenset[str]:
        """
        Returns:
            frozenset[str]: Every non-empty cookie value that ever entered the jar.
        """
        return frozenset(self._values)

    @property
    def names(self) -> frozenset[str]:
        """
        Returns:
            frozenset[str]: The cookie names the committed session holds.
        """
        return self._names

    def pending_items(self) -> frozenset[tuple[str, str]]:
        """
        Returns:
            frozenset[tuple[str, str]]: The ``(name, value)`` of every cookie in the pending
                jar; empty outside a handshake. A rotated value counts as a new item.
        """
        if self._pending is None:
            return frozenset()
        return frozenset((cookie.name, cookie.value or "") for cookie in self._pending.jar)

    def begin(self) -> None:
        """Start a handshake: an empty pending jar that collects the handshake's cookies."""
        self._pending = httpx.Cookies()

    def commit(self) -> None:
        """
        Make the pending jar the live session.

        Raises:
            RuntimeError: When no handshake is in progress.
        """
        if self._pending is None:
            raise RuntimeError("commit() without begin()")
        self._live = self._pending
        self._names = frozenset(cookie.name for cookie in self._live.jar)
        self._pending = None

    def rollback(self) -> None:
        """Discard the pending jar; the live session, if any, is untouched."""
        self._pending = None

    def absorb(self, raw: httpx.Response, *, handshake: bool) -> None:
        """
        Take the ``Set-Cookie`` headers of one response.

        Args:
            raw (httpx.Response): A response of a request to the target host.
            handshake (bool): ``True`` inside a handshake (every cookie is kept, in the
                pending jar); ``False`` for a live request (only a rotation of a held name).
        """
        if handshake:
            if self._pending is None:
                return
            self._pending.extract_cookies(raw)
            self._remember(self._pending)
            return
        if not self._names:
            return
        self._live.extract_cookies(raw)
        for cookie in list(self._live.jar):
            if cookie.name not in self._names:
                self._live.jar.clear(cookie.domain, cookie.path, cookie.name)
        self._remember(self._live)

    def pairs_for(self, url: str, *, handshake: bool) -> list[tuple[str, str]]:
        """
        The cookies to send to ``url``.

        Args:
            url (str): The absolute request URL.
            handshake (bool): Whether the request belongs to a handshake (reads the pending
                jar) or not (reads the live one).

        Returns:
            list[tuple[str, str]]: ``(name, value)`` pairs, empty for any host but the
                target host and for a cookie the browser rules would not send (``Secure`` on
                ``http``, another path, expired).
        """
        if (urlsplit(url).hostname or "").lower() != self._host:
            return []
        jar = self._pending if handshake and self._pending is not None else self._live
        request = httpx.Request("GET", url)
        jar.set_cookie_header(request)
        header = request.headers.get("cookie", "")
        pairs: list[tuple[str, str]] = []
        for part in header.split(";"):
            name, sep, value = part.strip().partition("=")
            if sep and name:
                pairs.append((name, value))
        return pairs

    def _remember(self, jar: httpx.Cookies) -> None:
        """
        Args:
            jar (httpx.Cookies): The jar that just absorbed a response; every value in it
                joins the scrub list.
        """
        for cookie in jar.jar:
            if cookie.value:
                self._values.add(cookie.value)


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
        secrets: Iterable[str] = (),
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
            secrets (Iterable[str]): Extra values to scrub from the report (the password).
        """
        self.jar = jar
        self.generation = 0
        self.relogins = 0
        self.max_relogins = max_relogins
        self.lost = False
        self.confirmed = True
        self.known_login_redirects: set[str] = set()
        self.failed_relogins = 0
        self._failures: list[str] = []
        self._is_login_url = is_login_url
        self._marker = re.compile(logged_out_marker) if logged_out_marker else None
        self._relogin = relogin
        self._confirm = confirm_dropped
        self._secrets: set[str] = {s for s in secrets if s}
        self._lock = asyncio.Lock()

    @property
    def secrets(self) -> frozenset[str]:
        """
        Returns:
            frozenset[str]: The password and every session cookie value ever held.
        """
        return frozenset(self._secrets | self.jar.values)

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
            self._marker.search(response.text[:_MARKER_BODY_CHARS])
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
            if self._relogin is None:
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

    def committed(self) -> None:
        """Record a committed (re)login: a new generation."""
        self.generation += 1

    def summary(self) -> LoginSummary:
        """
        Returns:
            LoginSummary: The facts for the scan metadata.
        """
        return LoginSummary(
            relogins=self.relogins, session_lost=self.lost, confirmed=self.confirmed
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
        return lines


__all__ = ["Session", "SessionJar"]
