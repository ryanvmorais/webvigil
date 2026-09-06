"""RateLimiter: concurrency cap and per-host delay spacing — RF-03."""

from __future__ import annotations

import asyncio

from webvigil.http.policy import RateLimiter


async def test_concurrency_is_capped() -> None:
    limiter = RateLimiter(concurrency=3, delay_ms=0)
    active = 0
    peak = 0

    async def worker() -> None:
        nonlocal active, peak
        async with limiter.slot("example.com"):
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1

    await asyncio.gather(*(worker() for _ in range(20)))
    assert peak <= 3


async def test_delay_spaces_requests_to_the_same_host() -> None:
    delay_s = 0.05
    requests = 5
    limiter = RateLimiter(concurrency=10, delay_ms=int(delay_s * 1000))
    stamps: list[float] = []

    async def worker() -> None:
        async with limiter.slot("example.com"):
            stamps.append(asyncio.get_running_loop().time())

    await asyncio.gather(*(worker() for _ in range(requests)))
    stamps.sort()
    span = stamps[-1] - stamps[0]
    # N requests to one host take at least (N-1)*delay; allow for OS timer slop.
    assert span >= (requests - 1) * delay_s * 0.75


async def test_delay_is_per_host() -> None:
    limiter = RateLimiter(concurrency=10, delay_ms=1000)
    start = asyncio.get_running_loop().time()
    await asyncio.gather(
        _acquire(limiter, "a.example.com"),
        _acquire(limiter, "b.example.com"),
    )
    assert asyncio.get_running_loop().time() - start < 0.5


async def _acquire(limiter: RateLimiter, host: str) -> None:
    async with limiter.slot(host):
        pass
