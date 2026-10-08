"""
Login throttling: slow down the guessing of the one account's password (security audit, 1.0.0).

The API has one account and, until now, no limit on login attempts: only the cost of Argon2
slowed a guesser down. After a few failures the same client, or the same username, must wait,
and the wait doubles with each further failure up to five minutes. Waiting, not locking: an
attacker can delay the owner by a few minutes at most, never lock them out.

State lives in memory, per process: a restart forgets it, which is acceptable for a
single-user, local-first service. Behind a reverse proxy every request has the proxy's address,
so the per-client key becomes one key for everybody and the per-username key does the work;
``X-Forwarded-For`` is not trusted because the client controls it.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable

# Failures that cost nothing: a mistyped password is not an attack.
FREE_ATTEMPTS = 5
# The longest wait, in seconds.
MAX_DELAY_S = 300
# A client that stays quiet this long is forgotten (and the table cannot grow forever).
FORGET_AFTER_S = 900


class LoginThrottle:
    """Counts failed logins per key and says how long a key must wait before trying again."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        """
        Args:
            clock (Callable[[], float]): A monotonic clock in seconds. Injectable so tests do
                not sleep. Defaults to :func:`time.monotonic`.
        """
        self._clock = clock
        self._failures: dict[str, tuple[int, float]] = {}

    def retry_after(self, *keys: str) -> int:
        """
        Args:
            *keys (str): The keys the attempt counts against (a client address, a username).

        Returns:
            int: The seconds the caller must wait, the longest over the keys; ``0`` when it may
                try now.
        """
        now = self._clock()
        self._forget(now)
        wait = 0.0
        for key in keys:
            count, last = self._failures.get(key, (0, 0.0))
            if count >= FREE_ATTEMPTS:
                delay = min(MAX_DELAY_S, 2 ** (count - FREE_ATTEMPTS))
                wait = max(wait, delay - (now - last))
        return max(0, math.ceil(wait))

    def record_failure(self, *keys: str) -> None:
        """
        Args:
            *keys (str): The keys a failed attempt counts against.
        """
        now = self._clock()
        for key in keys:
            count, _last = self._failures.get(key, (0, 0.0))
            self._failures[key] = (count + 1, now)

    def clear(self, *keys: str) -> None:
        """
        Args:
            *keys (str): The keys to forget, after a successful login.
        """
        for key in keys:
            self._failures.pop(key, None)

    def _forget(self, now: float) -> None:
        """
        Args:
            now (float): The current time on the throttle's clock.
        """
        stale = [
            key for key, (_count, last) in self._failures.items() if now - last > FORGET_AFTER_S
        ]
        for key in stale:
            del self._failures[key]
