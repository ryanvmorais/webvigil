"""
The async HTTP client wrapper: retries, manual redirects, and the destination rules.

No component talks to ``httpx2`` directly — they all go through
:class:`HttpClient`, so politeness, retries, timeouts, and scope enforcement
apply uniformly (RF-05, RF-03, RF-04). :meth:`HttpClient.request` carries any
HTTP method through the same machinery; :meth:`HttpClient.get` is a thin wrapper
over it (spec 006 ADR-9). What may be sent where is asked of the destination policy
(:mod:`webvigil.core.destination`, spec 026): configured ``[auth]`` cookies (spec 007)
and headers (spec 013 — a bearer token, an API key), and a credential header a caller
passes itself, go to the target origin (or its ``https`` upgrade) and to no other, and
never reach a report, a log line, or the scan metadata. Every connection goes through
the address guard (:mod:`webvigil.http.addresses`).
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import random
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from http.cookiejar import CookieJar, DefaultCookiePolicy
from types import TracebackType
from urllib.parse import urlsplit

import httpx2

from webvigil.core.config import ScanConfig
from webvigil.core.destination import (
    keeps_data,
    may_carry_credentials,
    may_request,
    without_credentials,
)
from webvigil.core.errors import OutOfScopeError, RequestFailed, ScanDeadlineExceeded
from webvigil.core.secrets import Secret, SecretKind
from webvigil.core.target import Target
from webvigil.core.text import replace_surrogates
from webvigil.core.urls import resolve_url
from webvigil.http.addresses import AddressGuard, BlockedAddressError, Resolver, install
from webvigil.http.decoding import ACCEPT_ENCODING, BodyDecoder
from webvigil.http.failures import failure_kind
from webvigil.http.policy import RateLimiter
from webvigil.http.session import Session, cookie_bytes, jar_text
from webvigil.http.tls import client_ssl_context, pin_proxy_trust

_MAX_ATTEMPTS = 3
_MAX_REDIRECT_HOPS = 10
_RETRY_STATUS = frozenset({500, 502, 503, 504})
_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
_IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
# A 307/308 replays the method and body; a 301/302/303 becomes a bodyless GET.
_REDIRECT_KEEPS_METHOD = frozenset({307, 308})
# RFC 1035, 2.3.4: a DNS label holds at most 63 octets.
_MAX_DNS_LABEL = 63

# spec 019. Set only inside the task that called ``HttpClient.handshake()`` / ``quiet()``, so a
# re-login running in one task never switches another task's requests into handshake mode.
_HANDSHAKE: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "webvigil_handshake", default=False
)
_QUIET: contextvars.ContextVar[bool] = contextvars.ContextVar("webvigil_quiet", default=False)
# spec 020: inside ``HttpClient.anonymous()`` a request carries only the headers its caller
# passes - no static ``[auth]`` cookie or header, no session jar.
_ANON: contextvars.ContextVar[bool] = contextvars.ContextVar("webvigil_anon", default=False)


class _TotalTimeout(httpx2.ReadTimeout):
    """A request that used up ``[http] total_timeout_s``: failed for good, never retried."""


_Params = dict[str, str] | list[tuple[str, str]]
# Multipart parts: field name -> (filename, content, content type) (spec 014 upload), or a
# list of (name, (filename | None, content, content type | None)) pairs, which keeps a
# repeated name and lets a part with no filename be a plain text field (spec 018).
_Files = (
    dict[str, tuple[str, bytes, str]] | list[tuple[str, tuple[str | None, str | bytes, str | None]]]
)

# Marks, on an httpx2 response, that its body was cut at ``max_body_bytes``.
_TRUNCATED_EXTENSION = "webvigil_truncated"
# Holds, on an httpx2 redirect response, the Location header that _hide_location took away from
# httpx2: the engine follows redirects itself and reads it from here.
_LOCATION_EXTENSION = "webvigil_location"

# Backoff between retries; module-level so tests can shrink them.
BACKOFF_BASE_S = 0.5
BACKOFF_JITTER_S = 0.25


@dataclass(slots=True)
class HttpStats:
    """
    Counters for one scan's HTTP activity, surfaced in reports and tests.

    Attributes:
        requests (int): Total requests actually sent (including retries).
        retries (int): Requests that were re-sent after a transport error or a
            retryable status.
        blocked_out_of_scope (int): Requests refused by the scope rule.
        crafted_requests (int): Requests that carried an injection payload or
            used a non-idempotent method.
        failed (int): Requests that failed for good: every attempt ended in a
            transport error or a timeout, so no response came back.
        truncated (int): Responses whose body was larger than ``max_body_bytes`` and was
            read only up to it.
        deadline_reached (bool): Whether the scan reached ``[scan] max_duration_s``.
        blocked_address (int): Requests not sent because their host resolved only to
            addresses the address guard refuses.
    """

    requests: int = 0
    retries: int = 0
    blocked_out_of_scope: int = 0
    crafted_requests: int = 0
    failed: int = 0
    truncated: int = 0
    deadline_reached: bool = False
    blocked_address: int = 0


# A target that went down mid-scan fails every request that follows. These two floors tell that
# apart from the odd timeout: enough failures to matter, and a large share of what was asked.
_UNREACHABLE_MIN_FAILED = 20
_UNREACHABLE_MIN_SHARE = 0.2


def unreachable_warning(stats: HttpStats) -> str | None:
    """
    The scan warning for a target that stopped answering, or ``None`` when it kept answering.

    Without it a target that crashes halfway leaves a scan that finishes "clean": every
    later request fails quietly and the missing findings look like a secure application.

    Args:
        stats (HttpStats): The counters of the finished scan.

    Returns:
        str | None: The warning text, or ``None`` below both floors.
    """
    asked = stats.requests - stats.retries  # one entry per request, however often it was retried
    if stats.failed < _UNREACHABLE_MIN_FAILED or stats.failed < asked * _UNREACHABLE_MIN_SHARE:
        return None
    return (
        f"{stats.failed} of {asked} requests got no response (connection errors or timeouts): "
        "the target may have stopped answering during the scan, so the results can be incomplete"
    )


def blocked_address_warning(stats: HttpStats) -> str | None:
    """
    The scan warning for requests the address guard stopped, or ``None`` when there were none.

    Args:
        stats (HttpStats): The counters of the finished scan.

    Returns:
        str | None: The warning text, or ``None`` when every host resolved to an allowed address.
    """
    if not stats.blocked_address:
        return None
    return (
        f"{stats.blocked_address} request(s) were not sent: a host in scope resolves only to "
        "internal addresses (loopback, private, link-local) while the target resolves to a "
        "public one, and the scan does not connect to internal addresses from a public target"
    )


def truncated_warning(stats: HttpStats, limit: int) -> str | None:
    """
    The scan warning for responses that were cut at the body limit, or ``None`` when none were.

    What lies past the limit is not analysed, so a scan that cut responses must say so.

    Args:
        stats (HttpStats): The counters of the finished scan.
        limit (int): The ``max_body_bytes`` the scan ran with.

    Returns:
        str | None: The warning text, or ``None`` when no body was cut.
    """
    if not stats.truncated:
        return None
    return (
        f"{stats.truncated} response(s) were larger than the {limit / (1024 * 1024):g} MiB read "
        "limit and were read only up to it ([http] max_body_bytes): what lies past it was not "
        "analysed"
    )


@dataclass(frozen=True, slots=True)
class RedirectHop:
    """
    One redirect the client followed while staying in scope.

    Attributes:
        from_url (str): URL that returned the redirect.
        to_url (str): URL the ``Location`` header pointed to.
        status_code (int): The 3xx status of the redirecting response.
    """

    from_url: str
    to_url: str
    status_code: int


@dataclass(frozen=True, eq=False, slots=True)
class Response:
    """
    A thin, read-only view of one fetched URL (after in-scope redirects).

    Attributes:
        url (str): Final URL after in-scope redirects.
        requested_url (str): URL originally asked for.
        status_code (int): HTTP status of the final response.
        headers (httpx2.Headers): Response headers of the final response.
        text (str): Decoded response body.
        content (bytes): Raw response body.
        elapsed_ms (float): Wall-clock time for the final request, in
            milliseconds.
        history (tuple[RedirectHop, ...]): Redirect hops followed. Defaults to
            empty.
        redirected_out_of_scope (bool): ``True`` when a redirect left scope, or would
            have replayed a body with credentials to a URL that may not receive them,
            and was not followed. Defaults to ``False``.
        final_location (str | None): The ``Location`` that was not followed, when
            applicable.
        truncated (bool): ``True`` when the body was larger than ``max_body_bytes`` and
            ``content`` / ``text`` hold only the first part.
    """

    url: str
    requested_url: str
    status_code: int
    headers: httpx2.Headers
    text: str
    content: bytes
    elapsed_ms: float
    history: tuple[RedirectHop, ...] = ()
    redirected_out_of_scope: bool = False
    final_location: str | None = None
    truncated: bool = False

    @property
    def is_html(self) -> bool:
        """
        Returns:
            bool: ``True`` when the response ``Content-Type`` names HTML.
        """
        return "html" in self.headers.get("content-type", "").lower()


def decode_text(content: bytes, content_type: str | None) -> str:
    """
    A body as text, in the charset ``content_type`` declares, or UTF-8 when that cannot decode.

    This is the decoding :attr:`Response.text` holds, so a part of a body (``robots.txt`` past
    its size limit) reads as the whole body would. ``charset=`` is the target's to write, and
    Python's codec registry also holds codecs that are not text encodings (``base64``, ``zlib``,
    ``hex``) or that refuse the ``replace`` error handler (``idna``): ``httpx2`` looks the name
    up and then fails inside ``.text`` with whatever that codec raises. Such a body is read as
    UTF-8 with replacement characters, as an unknown charset already is. Text that does decode
    can still hold a character no later step could encode: it is replaced here, where the text
    enters the engine.

    Args:
        content (bytes): The body, or a part of it.
        content_type (str | None): The response's ``Content-Type``, or ``None`` when it sent none.

    Returns:
        str: The decoded body, always encodable as UTF-8.
    """
    headers = () if content_type is None else (("content-type", content_type),)
    try:
        return replace_surrogates(httpx2.Response(200, headers=headers, content=content).text)
    except Exception:  # any codec's own error: the charset name came from the target
        return content.decode("utf-8", errors="replace")


def _host_of(url: str) -> str:
    """
    Args:
        url (str): An absolute URL.

    Returns:
        str: The lower-cased host, or ``""`` when the URL has none.
    """
    return (urlsplit(url).hostname or "").lower()


def _static_cookie_header(cookies: Sequence[Secret]) -> Secret | None:
    """
    Join the ``[auth]`` cookies into one ``Cookie`` header value, kept a secret.

    Each entry is ``name=value`` as written, the entries joined by ``"; "``, in the session jar's
    text form, because one ``Cookie`` header can carry both (UTF-8 on the wire).

    Args:
        cookies (Sequence[Secret]): The configured cookies, each named.

    Returns:
        Secret | None: The header value, or ``None`` when no cookie is configured.
    """
    if not cookies:
        return None
    joined = "; ".join(f"{cookie.name}={cookie.reveal()}" for cookie in cookies)
    return Secret(jar_text(joined.encode("utf-8")), kind=SecretKind.COOKIE, name="Cookie")


def _is_sendable(url: str) -> bool:
    """
    Whether ``httpx2`` can encode ``url`` and its host is a name DNS can carry.

    The URL comes from the scanned site. A host the IDNA encoder refuses or a character UTF-8
    cannot encode raises a ``UnicodeError`` while the request is built, and an empty or
    oversized DNS label raises one later, in the resolver or the TLS layer. None of them is a
    transport error, so each would end the scan. Only the URL is read here: the same exception
    from any other step is a defect, and it keeps propagating.

    Args:
        url (str): The absolute URL of a request.

    Returns:
        bool: ``False`` when the URL can never be sent. ``True`` for a URL ``httpx2`` refuses
            with :class:`httpx2.InvalidURL`, which the request path already reports by name.
    """
    try:
        parsed = httpx2.URL(url)
        _ = parsed.host  # decoded lazily, and building the request reads it
    except httpx2.InvalidURL:
        return True
    except UnicodeError:  # ``idna.IDNAError`` is one
        return False
    labels = parsed.raw_host.removesuffix(b".").split(b".")
    return all(0 < len(label) <= _MAX_DNS_LABEL for label in labels)


async def _hide_location(response: httpx2.Response) -> None:
    r"""
    Take a redirect's ``Location`` away from ``httpx2``, which would otherwise parse it.

    ``httpx2`` builds the next request of a redirect even with ``follow_redirects=False``, and a
    ``Location`` it cannot build one from (``https:\\host/``, which a browser reads as
    ``https://host/``; ``mailto:x``) raises ``InvalidURL`` there: the response never reaches the
    engine. The engine follows redirects itself, from :func:`~webvigil.core.urls.resolve_url`, so
    this response hook, which runs before that step, moves the header into the response's
    extensions: ``httpx2`` sees no redirect, and :meth:`HttpClient._send_with_redirects` reads the
    value from there and puts it back on the :class:`Response` it returns.

    Args:
        response (httpx2.Response): A response, before ``httpx2`` looks at its redirect.
    """
    if response.status_code in _REDIRECT_STATUS and "location" in response.headers:
        response.extensions[_LOCATION_EXTENSION] = response.headers["location"]
        del response.headers["location"]


class HttpClient:
    """
    Owns one ``httpx2.AsyncClient`` and the shared rate limiter for a scan.

    Must be used as an async context manager: the underlying client is created
    on ``__aenter__`` and closed on ``__aexit__``.
    """

    def __init__(
        self,
        target: Target,
        config: ScanConfig,
        *,
        transport: httpx2.BaseTransport | httpx2.AsyncBaseTransport | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        """
        Args:
            target (Target): The normalized target; its scope rule guards every
                request.
            config (ScanConfig): The resolved scan configuration (concurrency,
                delay, timeout, TLS verification, ``[auth]`` cookies).
            transport (httpx2.BaseTransport | httpx2.AsyncBaseTransport | None):
                Test seam — an ``httpx2`` ``ASGITransport`` / ``MockTransport``.
                ``None`` in normal operation.
            resolver (Resolver | None): Test seam — the name resolver of the address guard;
                the system resolver when ``None``.
        """
        self._target = target
        self._config = config
        # spec 007 / spec 013: attached to target-host requests only, never stored or logged;
        # secrets until a request is built (spec 024)
        self._cookie_header = _static_cookie_header(config.auth.cookies)
        self._auth_headers = config.auth.header_pairs
        self.addresses = AddressGuard(target.host, resolver=resolver)
        self.limiter = RateLimiter(config.http.concurrency, config.http.delay_ms)
        self.stats = HttpStats()
        self._max_body = config.http.max_body_bytes
        self._total_timeout = config.http.total_timeout_s
        self._max_duration = config.scan.max_duration_s
        self._deadline: float | None = None  # loop time; set when the client opens
        self._transport = transport  # test seam: an httpx2 ASGITransport / MockTransport
        self._client: httpx2.AsyncClient | None = None
        self._session: Session | None = None  # spec 019: set by use_session()

    async def __aenter__(self) -> HttpClient:
        """
        Open the underlying ``httpx2.AsyncClient``.

        Returns:
            HttpClient: This instance, ready to issue requests.
        """
        self._client = httpx2.AsyncClient(
            http2=True,
            follow_redirects=False,
            verify=client_ssl_context(verify=self._config.http.verify_tls),
            timeout=self._config.http.timeout_s,
            # only the codings BodyDecoder decodes within the body limit
            headers={
                "user-agent": self._config.http.user_agent,
                "accept-encoding": ACCEPT_ENCODING,
            },
            transport=self._transport,  # type: ignore[arg-type]
            event_hooks={"response": [_hide_location]},
            # The scanner sends the cookies of ``[auth]`` and of the login session, each under
            # its own destination rule, and nothing it picked up implicitly (spec 007). A jar
            # that accepts no cookie holds for retries and concurrent requests, which emptying
            # a shared jar before each request does not.
            cookies=CookieJar(policy=DefaultCookiePolicy(allowed_domains=[])),
        )
        if self._max_duration > 0:
            self._deadline = asyncio.get_running_loop().time() + self._max_duration
        if self._transport is None:
            install(self._client._transport, self.addresses)
            pin_proxy_trust(self._client)
        return self

    def _remaining(self) -> float | None:
        """
        Returns:
            float | None: Seconds left before ``[scan] max_duration_s``, or ``None`` with no
                limit.
        """
        if self._deadline is None:
            return None
        return self._deadline - asyncio.get_running_loop().time()

    def past_deadline(self) -> bool:
        """
        For work that sends no request, so no request would notice the limit.

        Returns:
            bool: Whether the scan is past ``[scan] max_duration_s``, which is then recorded.
        """
        remaining = self._remaining()
        if remaining is None or remaining > 0:
            return False
        self.stats.deadline_reached = True
        return True

    def _check_deadline(self, url: str) -> None:
        """
        Args:
            url (str): The request about to be sent.

        Raises:
            ScanDeadlineExceeded: When the scan is past ``[scan] max_duration_s``.
        """
        if self.past_deadline():
            raise ScanDeadlineExceeded(url, "the scan reached [scan] max_duration_s")

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close the underlying ``httpx2.AsyncClient`` if it is open."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def use_session(self, session: Session) -> None:
        """
        Attach a login session (spec 019): from now on its cookies ride on target-host requests.

        Args:
            session (Session): The session built by the orchestrator.
        """
        self._session = session

    @contextlib.asynccontextmanager
    async def handshake(self) -> AsyncIterator[None]:
        """
        Run requests as a login handshake: every cookie goes to a pending jar, no drop check.

        Scoped to the calling task (a ``ContextVar``), so concurrent scan requests are
        unaffected while a re-login runs.

        Yields:
            None: Control, with the handshake mode on.

        Raises:
            RuntimeError: When no session is attached.
        """
        if self._session is None:
            raise RuntimeError("handshake() needs use_session() first")
        self._session.jar.begin()
        handshake_token = _HANDSHAKE.set(True)
        quiet_token = _QUIET.set(True)
        try:
            yield
        finally:
            _QUIET.reset(quiet_token)
            _HANDSHAKE.reset(handshake_token)

    @contextlib.asynccontextmanager
    async def anonymous(self) -> AsyncIterator[None]:
        """
        Run requests as an anonymous visitor (spec 020): only the caller's own headers go out.

        No static ``[auth]`` cookie or header, no session jar, nothing absorbed and no drop
        detection; an explicit ``Cookie`` header the caller passes is sent as given. Used for the
        session-id samples, the fixation confirmation and the logout replay. Scoped to the calling
        task (a ``ContextVar``).

        Yields:
            None: Control, with the anonymous mode on for this task.
        """
        anon_token = _ANON.set(True)
        quiet_token = _QUIET.set(True)
        try:
            yield
        finally:
            _QUIET.reset(quiet_token)
            _ANON.reset(anon_token)

    @contextlib.asynccontextmanager
    async def quiet(self) -> AsyncIterator[None]:
        """
        Run requests with the live session but without drop detection (no recursion).

        Used by the ``check_url`` confirmation, which itself must not trigger a re-login.

        Yields:
            None: Control, with drop detection off for this task.
        """
        token = _QUIET.set(True)
        try:
            yield
        finally:
            _QUIET.reset(token)

    @property
    def _active_client(self) -> httpx2.AsyncClient:
        """
        Returns:
            httpx2.AsyncClient: The open client.

        Raises:
            RuntimeError: When accessed outside the async context manager.
        """
        if self._client is None:
            raise RuntimeError("HttpClient must be used as an async context manager")
        return self._client

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> Response:
        """
        Fetch ``url`` with a GET, following redirects only while they stay in scope.

        Args:
            url (str): The absolute URL to fetch.
            headers (dict[str, str] | None): Extra request headers; a credential header goes only
                where the scan's credentials may go.

        Returns:
            Response: The final response after in-scope redirects.

        Raises:
            OutOfScopeError: When ``url`` is out of scope.
            RequestFailed: When the request fails after exhausting retries.
        """
        return await self.request("GET", url, headers=headers)

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: _Params | None = None,
        data: _Params | None = None,
        content: str | bytes | None = None,
        files: _Files | None = None,
        headers: dict[str, str] | None = None,
        crafted: bool = False,
    ) -> Response:
        """
        Issue ``method url`` through the scope rule, rate limiter, retries, and the
        in-scope-only manual redirect loop.

        Args:
            method (str): HTTP method; case-insensitive.
            url (str): The absolute URL to request.
            params (dict[str, str] | list[tuple[str, str]] | None): Merged into
                the query string.
            data (dict[str, str] | list[tuple[str, str]] | None): A urlencoded
                form body (or the non-file fields of a multipart body when
                ``files`` is set).
            content (str | bytes | None): A raw request body (spec 012 XXE) —
                mutually exclusive with ``data`` / ``files``; set the
                ``Content-Type`` via ``headers``.
            files (dict[str, tuple[str, bytes, str]] | None): Multipart file
                parts, ``field -> (filename, content, content type)`` (spec 014
                file upload) — mutually exclusive with ``content``.
            headers (dict[str, str] | None): Extra request headers. A ``Cookie``, an
                ``Authorization`` or a configured ``[auth]`` header among them goes only where
                the scan's credentials may go, on the first request and on every hop; elsewhere
                it is dropped (spec 026, RF-03).
            crafted (bool): Mark this as an injection request for the
                ``crafted_requests`` counter. Defaults to ``False``.

        Returns:
            Response: The final response. A 301/302/303 redirect drops the
                method to GET and drops ``params`` and ``data``; a 307/308
                replays them, unless the body may hold a credential and the
                new URL may not receive one: that redirect is not followed.

        Raises:
            OutOfScopeError: When ``url`` is out of scope.
            RequestFailed: When the request fails after exhausting retries.
        """
        session = self._session
        seen = session.generation if session is not None else 0
        response = await self._send_with_redirects(
            method,
            url,
            params=params,
            data=data,
            content=content,
            files=files,
            headers=headers,
            crafted=crafted,
        )
        # spec 019: a response that says the session dropped earns one serialised re-login and
        # one retry of this request; the retry's answer is returned as it is.
        if (
            session is not None
            and not _QUIET.get()
            and may_carry_credentials(self._target, url)
            and session.looks_dropped(response)
            and await session.recover(seen, url)
        ):
            response = await self._send_with_redirects(
                method,
                url,
                params=params,
                data=data,
                content=content,
                files=files,
                headers=headers,
                crafted=crafted,
            )
            if session.looks_dropped(response):
                session.learn(url)
        return response

    def _credentialed(self) -> bool:
        """
        Whether a request now goes out with the scan's credentials, for :func:`keeps_data`.

        Returns:
            bool: ``True`` when the scan holds a session, a static cookie or an ``[auth]`` header,
                and the request is not an anonymous one. A request off the target origin carries
                none either way, which :func:`keeps_data` asks itself.
        """
        has_credentials = (
            self._session is not None or self._cookie_header is not None or bool(self._auth_headers)
        )
        return has_credentials and not _ANON.get()

    def _caller_headers(self, headers: dict[str, str] | None, url: str) -> dict[str, str] | None:
        """
        Args:
            headers (dict[str, str] | None): The headers the caller passed.
            url (str): The URL of the request or of the hop.

        Returns:
            dict[str, str] | None: The caller's headers without the credentials ``url`` may not
                get (:func:`without_credentials`, with this scan's ``[auth]`` header names).
        """
        auth_names = [name for name, _value in self._auth_headers]
        return without_credentials(self._target, headers, url, auth_names=auth_names)

    async def _send_with_redirects(
        self,
        method: str,
        url: str,
        *,
        params: _Params | None = None,
        data: _Params | None = None,
        content: str | bytes | None = None,
        files: _Files | None = None,
        headers: dict[str, str] | None = None,
        crafted: bool = False,
    ) -> Response:
        """
        Send one request and follow its in-scope redirects (the body of :meth:`request`).

        Args:
            method (str): HTTP method; case-insensitive.
            url (str): The absolute URL to request.
            params (dict[str, str] | list[tuple[str, str]] | None): Query parameters.
            data (dict[str, str] | list[tuple[str, str]] | None): Form body.
            content (str | bytes | None): Raw request body.
            files (dict[str, tuple[str, bytes, str]] | None): Multipart parts.
            headers (dict[str, str] | None): Extra request headers; their credentials go only
                where :func:`may_carry_credentials` allows, on every request of the chain.
            crafted (bool): Mark this as an injection request.

        Returns:
            Response: The final response after in-scope redirects.

        Raises:
            OutOfScopeError: When ``url`` is out of scope.
            RequestFailed: When the request fails after exhausting retries, when ``url`` or a
                redirect's ``Location`` is malformed, or when the body cannot be decoded.
        """
        method = method.upper()
        if content is not None and files is not None:
            raise ValueError("request() takes content or files, not both")
        if resolve_url(url, "") is None:
            # built from the site's own text (a link, a form action): not sent, and not counted
            # as a failure, which would read as a target that stopped answering
            raise RequestFailed(url, "malformed URL")
        if not may_request(self._target, url):
            self.stats.blocked_out_of_scope += 1
            raise OutOfScopeError(url)

        requested_url = url
        current_url = url
        current_method = method
        current_params = params
        current_data = data
        current_files = files
        hops: list[RedirectHop] = []
        redirected_out = False
        final_location: str | None = None

        raw = await self._request_with_retry(
            current_method,
            current_url,
            self._caller_headers(headers, current_url),
            current_params,
            current_data,
            content,
            current_files,
            crafted,
        )
        for _ in range(_MAX_REDIRECT_HOPS):
            location = raw.extensions.get(_LOCATION_EXTENSION)  # see _hide_location
            if location is None:
                break
            target_url = resolve_url(current_url, location)
            if target_url is None:
                raise RequestFailed(current_url, "the Location header is not a valid URL")
            replays_data = raw.status_code in _REDIRECT_KEEPS_METHOD and bool(
                content or current_data or current_files or current_params
            )
            if not may_request(self._target, target_url) or (
                replays_data
                and not keeps_data(
                    self._target, current_url, target_url, credentialed=self._credentialed()
                )
            ):
                redirected_out = True
                final_location = target_url
                break
            hops.append(RedirectHop(current_url, target_url, raw.status_code))
            current_url = target_url
            if raw.status_code not in _REDIRECT_KEEPS_METHOD:
                current_method, current_params, current_data, content, current_files = (
                    "GET",
                    None,
                    None,
                    None,
                    None,
                )
            raw = await self._request_with_retry(
                current_method,
                current_url,
                self._caller_headers(headers, current_url),
                current_params,
                current_data,
                content,
                current_files,
                crafted,
            )

        response_headers = raw.headers
        if (location := raw.extensions.get(_LOCATION_EXTENSION)) is not None:
            response_headers = response_headers.copy()
            response_headers["location"] = location  # what the server sent, for the checks
        return Response(
            url=str(raw.url),
            requested_url=requested_url,
            status_code=raw.status_code,
            headers=response_headers,
            text=decode_text(raw.content, raw.headers.get("content-type")),
            content=raw.content,
            elapsed_ms=raw.elapsed.total_seconds() * 1000,
            history=tuple(hops),
            redirected_out_of_scope=redirected_out,
            final_location=final_location,
            truncated=bool(raw.extensions.get(_TRUNCATED_EXTENSION, False)),
        )

    async def _read_capped(self, streamed: httpx2.Response) -> httpx2.Response:
        """
        Read a streamed response body up to ``max_body_bytes`` and close the connection.

        ``httpx2`` would read the whole body into memory, however large: a hostile server, a
        multi-gigabyte file reached by a probe, or a compressed body that inflates a thousandfold
        could exhaust the scanner. The limit is on the *decompressed* size, and a cut body is
        marked and counted so the scan can say so.

        Args:
            streamed (httpx2.Response): A response obtained with ``stream=True``.

        Returns:
            httpx2.Response: The same response with its (possibly cut) body loaded, as
                ``Response.aread`` would leave it.
        """
        decoder = BodyDecoder(
            streamed.headers.get_list("content-encoding", split_commas=True), self._max_body
        )
        try:
            async for chunk in streamed.aiter_raw():
                if decoder.feed(chunk):
                    break
            else:
                decoder.finish()
        finally:
            await streamed.aclose()
        streamed._content = decoder.body  # what Response.aread() does, with the cap
        if decoder.cut:
            streamed.extensions[_TRUNCATED_EXTENSION] = True
            self.stats.truncated += 1
        return streamed

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        params: _Params | None,
        data: _Params | None,
        content: str | bytes | None,
        files: _Files | None,
        crafted: bool,
    ) -> httpx2.Response:
        """
        Send one request with retry and the ``[auth]`` cookie / header handling, no redirect loop.

        Idempotent methods are retried on a transport error and on a retryable
        5xx; a non-idempotent method is retried only on a pre-send connect
        error, never after a read timeout.

        Args:
            method (str): Upper-cased HTTP method.
            url (str): The absolute URL to request.
            headers (dict[str, str] | None): Extra request headers.
            params (dict[str, str] | list[tuple[str, str]] | None): Query
                parameters.
            data (dict[str, str] | list[tuple[str, str]] | None): Form body.
            content (str | bytes | None): Raw request body.
            files (dict[str, tuple[str, bytes, str]] | None): Multipart file
                parts (spec 014).
            crafted (bool): Whether to count this against ``crafted_requests``.

        Returns:
            httpx2.Response: The raw response.

        Raises:
            RequestFailed: When every attempt fails, or at once when ``httpx2`` cannot build
                the URL or decode the body.
        """
        if not _is_sendable(url):
            # the same on every attempt, and not a target that stopped answering: not counted
            raise RequestFailed(url, "malformed URL")
        idempotent = method in _IDEMPOTENT
        req_headers = dict(headers or {})
        on_target = may_carry_credentials(self._target, url)
        anonymous = _ANON.get()
        session = None if anonymous else self._session
        handshake = _HANDSHAKE.get()
        # the static cookies, revealed for this request only (spec 024)
        static_header = "" if self._cookie_header is None else self._cookie_header.reveal()
        cookie_header = "" if anonymous else static_header
        if session is not None and on_target:
            session_pairs = session.jar.pairs_for(url, handshake=handshake)
            if session_pairs:
                held = {name for name, _value in session_pairs}
                # a cookie the login set wins over a static one of the same name (spec 019)
                static = [
                    part.strip()
                    for part in static_header.split(";")
                    if part.strip() and part.strip().partition("=")[0] not in held
                ]
                cookie_header = "; ".join([*static, *(f"{n}={v}" for n, v in session_pairs)])
        if cookie_header and on_target:
            existing = req_headers.get("cookie")
            req_headers["cookie"] = f"{existing}; {cookie_header}" if existing else cookie_header
        jar_cookie = req_headers.get("cookie")  # read before the [auth] headers can add one
        # spec 013: configured [auth] headers, target-host only, without clobbering a header
        # the caller already set for this request (case-insensitive).
        if self._auth_headers and on_target and not anonymous:
            present = {name.lower() for name in req_headers}
            for name, value in self._auth_headers:
                if name.lower() not in present:
                    req_headers[name] = value.reveal()
        # httpx2 encodes a text header as ASCII, so a cookie outside it goes out as its own bytes
        wire_headers: dict[str, str] | httpx2.Headers = req_headers
        if jar_cookie is not None and not jar_cookie.isascii():
            wire_headers = httpx2.Headers(
                [
                    (
                        name.encode("ascii"),
                        cookie_bytes(value) if name == "cookie" else value.encode("ascii"),
                    )
                    for name, value in req_headers.items()
                ]
            )
        last_error: str = "unknown error"
        for attempt in range(_MAX_ATTEMPTS):
            if attempt:
                self.stats.retries += 1
                await asyncio.sleep(
                    BACKOFF_BASE_S * (2**attempt) + random.uniform(0, BACKOFF_JITTER_S)
                )
            self._check_deadline(url)
            try:
                async with self.limiter.slot(_host_of(url)):
                    self._check_deadline(url)  # the wait for a slot may have used it up
                    # httpx2's stubs are narrower than what it accepts at runtime
                    # (a list of pairs works for both params and a form body).
                    request = self._active_client.build_request(
                        method,
                        url,
                        params=params,  # type: ignore[arg-type]
                        data=data,  # type: ignore[arg-type]
                        content=content,
                        files=files,
                        headers=wire_headers,
                    )
                    self.stats.requests += 1
                    if crafted or not idempotent:
                        self.stats.crafted_requests += 1
                    # ``timeout_s`` limits each operation, so a server that drips one byte every
                    # few seconds never trips it: this is the deadline for the whole exchange,
                    # sending to last byte (issue #140). It starts after the slot is held, so
                    # waiting for a free slot is not counted against the server.
                    # The scan deadline, when nearer, bounds the exchange too.
                    limit = self._total_timeout
                    remaining = self._remaining()
                    by_deadline = remaining is not None and remaining < limit
                    if remaining is not None and by_deadline:
                        limit = remaining
                    try:
                        async with asyncio.timeout(limit):
                            response = await self._read_capped(
                                await self._active_client.send(request, stream=True)
                            )
                    except TimeoutError as exc:
                        if by_deadline:
                            self.stats.deadline_reached = True
                            raise ScanDeadlineExceeded(
                                url, "the scan reached [scan] max_duration_s"
                            ) from exc
                        raise _TotalTimeout(
                            f"no complete response within {self._total_timeout:g} s "
                            "([http] total_timeout_s)"
                        ) from exc
            except (httpx2.InvalidURL, httpx2.DecodingError) as exc:
                # A URL httpx2 refuses to build (one over 64 KiB, say) or a body that does not
                # decode as its Content-Encoding claims: the same answer on every attempt.
                # ``from None`` here and below: a chained library error would print its text
                # again in any traceback of this one.
                raise RequestFailed(url, failure_kind(exc)) from None
            except (httpx2.TransportError, httpx2.TimeoutException) as exc:
                last_error = failure_kind(exc)
                if isinstance(exc.__cause__, BlockedAddressError):
                    # the resolution is pinned for the scan: a retry would be refused the same way
                    self.stats.blocked_address += 1
                    raise RequestFailed(url, last_error) from None
                # A server that used the whole total deadline once would use it again: the
                # request is not retried, so a slow target costs one deadline per request.
                if isinstance(exc, _TotalTimeout):
                    self.stats.failed += 1
                    # this text is written above and names the setting to raise
                    raise RequestFailed(url, f"{last_error}: {exc}") from None
                # A non-idempotent request is only retried when it never reached the
                # server (a pre-send connect error) — never on a read timeout.
                if idempotent or isinstance(exc, httpx2.ConnectError):
                    continue
                self.stats.failed += 1
                raise RequestFailed(url, last_error) from None
            if session is not None and on_target:
                session.jar.absorb(response, handshake=handshake)
            if idempotent and response.status_code in _RETRY_STATUS and attempt < _MAX_ATTEMPTS - 1:
                last_error = f"HTTP {response.status_code}"
                continue
            return response
        self.stats.failed += 1
        raise RequestFailed(url, last_error)


__all__ = [
    "HttpClient",
    "HttpStats",
    "RedirectHop",
    "Response",
    "blocked_address_warning",
    "decode_text",
    "truncated_warning",
    "unreachable_warning",
]
