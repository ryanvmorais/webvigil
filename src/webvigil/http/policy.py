"""
The "good neighbor" rate limiter: a concurrency cap plus a per-host request delay.

Every outbound request in the engine — crawler fetches, check probes, the TLS
handshake — acquires a slot here, so RF-03 holds no matter which component is
talking to the target.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager


class RateLimiter:
    """
    Bounds in-flight requests and spaces consecutive requests to the same host.

    The concurrency cap is a shared semaphore; the delay is enforced per host
    by tracking the earliest time the next request to that host may start.
    """

    def __init__(self, concurrency: int, delay_ms: int) -> None:
        """
        Args:
            concurrency (int): Maximum requests in flight at once. Values below
                1 are clamped to 1.
            delay_ms (int): Minimum gap between consecutive requests to the same
                host, in milliseconds. Negative values are treated as 0.
        """
        self._semaphore = asyncio.Semaphore(max(1, concurrency))
        self._delay = max(0, delay_ms) / 1000
        self._next_allowed: dict[str, float] = {}
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def slot(self, host: str) -> AsyncIterator[None]:
        """
        Acquire a request slot for ``host``, waiting for the delay window if needed.

        Holds a concurrency slot for the duration of the ``async with`` block
        and, when a delay is configured, sleeps until this host's next-allowed
        time before yielding.

        Args:
            host (str): The host the caller is about to request.

        Yields:
            None: Once the slot is held and the per-host delay has elapsed.
        """
        async with self._semaphore:
            if self._delay:
                loop = asyncio.get_running_loop()
                async with self._lock:
                    now = loop.time()
                    start_at = max(now, self._next_allowed.get(host, 0.0))
                    self._next_allowed[host] = start_at + self._delay
                wait = start_at - now
                if wait > 0:
                    await asyncio.sleep(wait)
            yield
