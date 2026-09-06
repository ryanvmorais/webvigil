"""The async HTTP client wrapper: retries, manual redirects, and the scope guard.

No component talks to ``httpx`` directly — they all go through :class:`HttpClient`, so
politeness, retries, timeouts, and scope enforcement apply uniformly (RF-05, RF-03, RF-04).
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

# Backoff between retries; module-level so tests can shrink them.
BACKOFF_BASE_S = 0.5
BACKOFF_JITTER_S = 0.25


@dataclass(slots=True)
class HttpStats:
    """Counters for one scan's HTTP activity, surfaced in reports and tests."""

    requests: int = 0
    retries: int = 0
    blocked_out_of_scope: int = 0


@dataclass(frozen=True, slots=True)
class RedirectHop:
    from_url: str
    to_url: str
    status_code: int


@dataclass(frozen=True, eq=False, slots=True)
class Response:
    """A thin, read-only view of one fetched URL (after in-scope redirects)."""

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
        return "html" in self.headers.get("content-type", "").lower()


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


class HttpClient:
    """Owns one ``httpx.AsyncClient`` and the shared rate limiter for a scan."""

    def __init__(
        self,
        target: Target,
        config: ScanConfig,
        *,
        transport: httpx.BaseTransport | httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._target = target
        self._config = config
        self._guard = ScopeGuard(target)
        self.limiter = RateLimiter(config.http.concurrency, config.http.delay_ms)
        self.stats = HttpStats()
        self._transport = transport  # test seam: an httpx ASGITransport / MockTransport
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> HttpClient:
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
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def _active_client(self) -> httpx.AsyncClient:
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
        """Fetch ``url``, following redirects only while they stay in scope."""
        if not allow_out_of_scope and not self._guard.allows(url):
            self.stats.blocked_out_of_scope += 1
            self._guard.check(url)  # raises OutOfScopeError

        requested_url = url
        current_url = url
        hops: list[RedirectHop] = []
        redirected_out = False
        final_location: str | None = None

        raw = await self._request_with_retry(current_url, headers)
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
            raw = await self._request_with_retry(current_url, headers)

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

    async def _request_with_retry(self, url: str, headers: dict[str, str] | None) -> httpx.Response:
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
                    response = await self._active_client.get(url, headers=headers)
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                continue
            if response.status_code in _RETRY_STATUS and attempt < _MAX_ATTEMPTS - 1:
                last_error = f"HTTP {response.status_code}"
                continue
            return response
        raise RequestFailed(url, last_error)


__all__ = ["HttpClient", "HttpStats", "RedirectHop", "Response"]
