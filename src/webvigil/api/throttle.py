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

The table is bounded, because its keys come from unauthenticated requests: a key is never kept
longer than ``MAX_KEY_CHARS``, and when ``MAX_KEYS`` are held the key that failed longest ago is
dropped to make room.
"""

from __future__ import annotations

import hashlib
import math
import time
from collections.abc import Callable

# Failures that cost nothing: a mistyped password is not an attack.
FREE_ATTEMPTS = 5
# The longest wait, in seconds.
MAX_DELAY_S = 300
# A client that stays quiet this long is forgotten (and the table cannot grow forever).
FORGET_AFTER_S = 900
# Distinct keys held at once. Each costs a short string and a tuple, so this is about a megabyte;
# more than a single-user service ever sees, and the cap that keeps a flood of made-up usernames
# from growing the process without limit.
MAX_KEYS = 10_000
# A key longer than this is replaced by its SHA-256, so a key never holds more than this many
# characters whatever the caller built it from.
MAX_KEY_CHARS = 128


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
        for key in map(_bounded, keys):
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
        for key in map(_bounded, keys):
            # Pop and re-insert, so the dict stays ordered by the last failure and the first
            # entry is always the one to drop when the table is full.
            count, _last = self._failures.pop(key, (0, 0.0))
            if len(self._failures) >= MAX_KEYS:
                del self._failures[next(iter(self._failures))]
            self._failures[key] = (count + 1, now)

    def clear(self, *keys: str) -> None:
        """
        Args:
            *keys (str): The keys to forget, after a successful login.
        """
        for key in map(_bounded, keys):
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


def _bounded(key: str) -> str:
    """
    Args:
        key (str): A throttle key, possibly built from what an unauthenticated client sent.

    Returns:
        str: ``key`` itself when it is at most ``MAX_KEY_CHARS`` long, otherwise ``"sha256:"``
            and the hex digest of its UTF-8 bytes: the same input always maps to the same key.
    """
    if len(key) <= MAX_KEY_CHARS:
        return key
    return "sha256:" + hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest()
