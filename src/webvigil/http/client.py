"""
The async HTTP client wrapper: retries, manual redirects, and the scope guard.

No component talks to ``httpx`` directly — they all go through
:class:`HttpClient`, so politeness, retries, timeouts, and scope enforcement
apply uniformly (RF-05, RF-03, RF-04). :meth:`HttpClient.request` carries any
HTTP method through the same machinery; :meth:`HttpClient.get` is a thin wrapper
over it (spec 006 ADR-9). Configured ``[auth]`` cookies (spec 007) and headers
(spec 013 — a bearer token, an API key) are attached to requests whose host is
the target host and to no other, and never reach a report, a log line, or the
scan metadata.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from types import TracebackType
from urllib.parse import urljoin, urlsplit

import httpx

from webvigil.core.config import ScanConfig
from webvigil.core.errors import RequestFailed
from webvigil.core.target import Target
from webvigil.http.policy import RateLimiter
from webvigil.http.scope_guard import ScopeGuard

_MAX_ATTEMPTS = 3
_MAX_REDIRECT_HOPS = 10
_RETRY_STATUS = frozenset({500, 502, 503, 504})
_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
_IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
# A 307/308 replays the method and body; a 301/302/303 becomes a bodyless GET.
_REDIRECT_KEEPS_METHOD = frozenset({307, 308})

_Params = dict[str, str] | list[tuple[str, str]]

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
        blocked_out_of_scope (int): Requests refused by the scope guard.
        crafted_requests (int): Requests that carried an injection payload or
            used a non-idempotent method.
    """

    requests: int = 0
    retries: int = 0
    blocked_out_of_scope: int = 0
    crafted_requests: int = 0


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
        headers (httpx.Headers): Response headers of the final response.
        text (str): Decoded response body.
        content (bytes): Raw response body.
        elapsed_ms (float): Wall-clock time for the final request, in
            milliseconds.
        history (tuple[RedirectHop, ...]): Redirect hops followed. Defaults to
            empty.
        redirected_out_of_scope (bool): ``True`` when a redirect left scope and
            was not followed. Defaults to ``False``.
        final_location (str | None): The out-of-scope ``Location`` that was not
            followed, when applicable.
    """

    url: str
    requested_url: str
    status_code: int
    headers: httpx.Headers
    text: str
    content: bytes
    elapsed_ms: float
    history: tuple[RedirectHop, ...] = ()
    redirected_out_of_scope: bool = False
    final_location: str | None = None

    @property
    def is_html(self) -> bool:
        """
        Returns:
            bool: ``True`` when the response ``Content-Type`` names HTML.
        """
        return "html" in self.headers.get("content-type", "").lower()


def _host_of(url: str) -> str:
    """
    Args:
        url (str): An absolute URL.

    Returns:
        str: The lower-cased host, or ``""`` when the URL has none.
    """
    return (urlsplit(url).hostname or "").lower()


class HttpClient:
    """
    Owns one ``httpx.AsyncClient`` and the shared rate limiter for a scan.

    Must be used as an async context manager: the underlying client is created
    on ``__aenter__`` and closed on ``__aexit__``.
    """

    def __init__(
        self,
        target: Target,
        config: ScanConfig,
        *,
        transport: httpx.BaseTransport | httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """
        Args:
            target (Target): The normalized target; its scope rule guards every
                request.
            config (ScanConfig): The resolved scan configuration (concurrency,
                delay, timeout, TLS verification, ``[auth]`` cookies).
            transport (httpx.BaseTransport | httpx.AsyncBaseTransport | None):
                Test seam — an ``httpx`` ``ASGITransport`` / ``MockTransport``.
                ``None`` in normal operation.
        """
        self._target = target
        self._config = config
        # spec 007 / spec 013: attached to target-host requests only, never stored or logged.
        self._cookie_header = config.auth.as_header
        self._auth_headers = config.auth.header_pairs
        self._guard = ScopeGuard(target)
        self.limiter = RateLimiter(config.http.concurrency, config.http.delay_ms)
        self.stats = HttpStats()
        self._transport = transport  # test seam: an httpx ASGITransport / MockTransport
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> HttpClient:
        """
        Open the underlying ``httpx.AsyncClient``.

        Returns:
            HttpClient: This instance, ready to issue requests.
        """
        self._client = httpx.AsyncClient(
            http2=True,
            follow_redirects=False,
            verify=self._config.http.verify_tls,
            timeout=self._config.http.timeout_s,
            headers={"user-agent": self._config.http.user_agent},
            transport=self._transport,  # type: ignore[arg-type]
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close the underlying ``httpx.AsyncClient`` if it is open."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def _active_client(self) -> httpx.AsyncClient:
        """
        Returns:
            httpx.AsyncClient: The open client.

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
        allow_out_of_scope: bool = False,
    ) -> Response:
        """
        Fetch ``url`` with a GET, following redirects only while they stay in scope.

        Args:
            url (str): The absolute URL to fetch.
            headers (dict[str, str] | None): Extra request headers.
            allow_out_of_scope (bool): Skip the scope guard for this request.
                Defaults to ``False``.

        Returns:
            Response: The final response after in-scope redirects.

        Raises:
            OutOfScopeError: When ``url`` is out of scope and
                ``allow_out_of_scope`` is ``False``.
            RequestFailed: When the request fails after exhausting retries.
        """
        return await self.request(
            "GET", url, headers=headers, allow_out_of_scope=allow_out_of_scope
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: _Params | None = None,
        data: _Params | None = None,
        content: str | bytes | None = None,
        headers: dict[str, str] | None = None,
        allow_out_of_scope: bool = False,
        crafted: bool = False,
    ) -> Response:
        """
        Issue ``method url`` through the scope guard, rate limiter, retries, and the
        in-scope-only manual redirect loop.

        Args:
            method (str): HTTP method; case-insensitive.
            url (str): The absolute URL to request.
            params (dict[str, str] | list[tuple[str, str]] | None): Merged into
                the query string.
            data (dict[str, str] | list[tuple[str, str]] | None): A urlencoded
                form body.
            content (str | bytes | None): A raw request body (spec 012 XXE) —
                mutually exclusive with ``data``; set the ``Content-Type`` via
                ``headers``.
            headers (dict[str, str] | None): Extra request headers.
            allow_out_of_scope (bool): Skip the scope guard for this request.
                Defaults to ``False``.
            crafted (bool): Mark this as an injection request for the
                ``crafted_requests`` counter. Defaults to ``False``.

        Returns:
            Response: The final response. A 301/302/303 redirect drops the
                method to GET and drops ``params`` and ``data``; a 307/308
                replays them.

        Raises:
            OutOfScopeError: When ``url`` is out of scope and
                ``allow_out_of_scope`` is ``False``.
            RequestFailed: When the request fails after exhausting retries.
        """
        method = method.upper()
        if not allow_out_of_scope and not self._guard.allows(url):
            self.stats.blocked_out_of_scope += 1
            self._guard.check(url)  # raises OutOfScopeError

        requested_url = url
        current_url = url
        current_method = method
        current_params = params
        current_data = data
        hops: list[RedirectHop] = []
        redirected_out = False
        final_location: str | None = None

        raw = await self._request_with_retry(
            current_method, current_url, headers, current_params, current_data, content, crafted
        )
        for _ in range(_MAX_REDIRECT_HOPS):
            if raw.status_code not in _REDIRECT_STATUS or "location" not in raw.headers:
                break
            target_url = urljoin(current_url, raw.headers["location"])
            if not self._guard.allows(target_url):
                redirected_out = True
                final_location = target_url
                break
            hops.append(RedirectHop(current_url, target_url, raw.status_code))
            current_url = target_url
            if raw.status_code not in _REDIRECT_KEEPS_METHOD:
                current_method, current_params, current_data, content = "GET", None, None, None
            raw = await self._request_with_retry(
                current_method, current_url, headers, current_params, current_data, content, crafted
            )

        return Response(
            url=str(raw.url),
            requested_url=requested_url,
            status_code=raw.status_code,
            headers=raw.headers,
            text=raw.text,
            content=raw.content,
            elapsed_ms=raw.elapsed.total_seconds() * 1000,
            history=tuple(hops),
            redirected_out_of_scope=redirected_out,
            final_location=final_location,
        )

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        params: _Params | None,
        data: _Params | None,
        content: str | bytes | None,
        crafted: bool,
    ) -> httpx.Response:
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
            crafted (bool): Whether to count this against ``crafted_requests``.

        Returns:
            httpx.Response: The raw response.

        Raises:
            RequestFailed: When every attempt fails.
        """
        idempotent = method in _IDEMPOTENT
        # The scanner sends exactly the cookies configured in ``[auth]`` and nothing it
        # picked up implicitly: drop anything the target set via ``Set-Cookie`` so a scan is
        # deterministic and authentication stays config-driven (spec 007).
        self._active_client.cookies.clear()
        req_headers = dict(headers or {})
        if self._cookie_header and _host_of(url) == self._target.host:
            existing = req_headers.get("cookie")
            req_headers["cookie"] = (
                f"{existing}; {self._cookie_header}" if existing else self._cookie_header
            )
        # spec 013: configured [auth] headers, target-host only, without clobbering a header
        # the caller already set for this request (case-insensitive).
        if self._auth_headers and _host_of(url) == self._target.host:
            present = {name.lower() for name in req_headers}
            for name, value in self._auth_headers:
                if name.lower() not in present:
                    req_headers[name] = value
        last_error: str = "unknown error"
        for attempt in range(_MAX_ATTEMPTS):
            if attempt:
                self.stats.retries += 1
                await asyncio.sleep(
                    BACKOFF_BASE_S * (2**attempt) + random.uniform(0, BACKOFF_JITTER_S)
                )
            try:
                async with self.limiter.slot(_host_of(url)):
                    self.stats.requests += 1
                    if crafted or not idempotent:
                        self.stats.crafted_requests += 1
                    # httpx's stubs are narrower than what it accepts at runtime
                    # (a list of pairs works for both params and a form body).
                    response = await self._active_client.request(
                        method,
                        url,
                        params=params,  # type: ignore[arg-type]
                        data=data,  # type: ignore[arg-type]
                        content=content,
                        headers=req_headers,
                    )
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                # A non-idempotent request is only retried when it never reached the
                # server (a pre-send connect error) — never on a read timeout.
                if idempotent or isinstance(exc, httpx.ConnectError):
                    continue
                raise RequestFailed(url, last_error) from exc
            if idempotent and response.status_code in _RETRY_STATUS and attempt < _MAX_ATTEMPTS - 1:
                last_error = f"HTTP {response.status_code}"
                continue
            return response
        raise RequestFailed(url, last_error)


__all__ = ["HttpClient", "HttpStats", "RedirectHop", "Response"]
