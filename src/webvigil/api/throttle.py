"""
Login throttling: slow down the guessing of the one account's password (security audit, 1.0.0).

The API has one account and, until now, no limit on login attempts: only the cost of Argon2
slowed a guesser down. After a few failures a client must wait, and the wait doubles with each
further failure up to five minutes. The wait belongs to the client, so a single client guessing
delays only itself. Who the client is comes from :mod:`webvigil.api.client_address`.

Guesses spread over many addresses are contained by a second, shared limit per username: a high
threshold inside a short window, so that one client is always stopped by its own wait first. That
limit falls on everyone using the username, so many addresses can still delay its login for as
long as the guessing lasts. The password change re-checks the current password under its own
per-user key.

State lives in memory, per process: a restart forgets it, which is acceptable for a
single-user, local-first service.

The table is bounded, because its keys come from unauthenticated requests: a key is never kept
longer than ``MAX_KEY_CHARS``, and when ``MAX_KEYS`` are held the key that failed longest ago *and
is not waiting* is dropped to make room. Dropping a waiting key would hand its client the attempts
it is waiting for, so a table holding nothing else refuses a new key until the first wait ends.

Each check costs a full Argon2 in memory and CPU whatever the username, so only
``MAX_CONCURRENT_CHECKS`` run at once and the excess is answered at once. The hash of the initial
setup takes the same slots.

The login route runs on a thread pool, so requests arrive in parallel. Every method takes one lock,
and the routes check the wait and count the attempt as a failure in the same step: a burst of
parallel requests cannot all pass the check before the first of them is counted. A login that
succeeds takes its attempt back.
"""

from __future__ import annotations

import hashlib
import math
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from itertools import islice
from typing import NamedTuple

# Failures that cost nothing: a mistyped password is not an attack.
FREE_ATTEMPTS = 5
# The longest wait, in seconds.
MAX_DELAY_S = 300
# A client that stays quiet this long is forgotten (and the table cannot grow forever).
FORGET_AFTER_S = 900
# Distinct keys held at once. Each costs a short string and a tuple, so this is about a megabyte;
# more than a single-user service ever sees, and the cap that keeps made-up usernames from growing
# the process without limit.
MAX_KEYS = 10_000
# A key longer than this is replaced by its SHA-256, so a key never holds more than this many
# characters whatever the caller built it from.
MAX_KEY_CHARS = 128
# The shared limit per username. Its own doubling wait keeps one client under this threshold
# inside the window, so only several clients at once can reach it. The wait is at most the window:
# short, because it is the one limit that also delays the owner.
USER_WINDOW_S = 30
USER_MAX_ATTEMPTS = 20
# Argon2 checks of a login or the initial setup running at once. Each one holds its full memory
# cost, so this bounds what those routes can use, and one person never logs in this many times at
# once.
MAX_CONCURRENT_CHECKS = 4
# What a login turned away for lack of a free check is told: the checks in progress end in well
# under a second.
BUSY_RETRY_S = 1


class _Entry(NamedTuple):
    """
    What the table holds for one key.

    Attributes:
        attempts (int): Attempts counted.
        stamp (float): The last failure or, for a windowed key, when its window opened.
        windowed (bool): ``True`` for a username's shared limit, ``False`` for a doubling wait.
    """

    attempts: int
    stamp: float
    windowed: bool = False


class LoginThrottle:
    """Counts failed logins per key and says how long a key must wait before trying again."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_concurrent_checks: int = MAX_CONCURRENT_CHECKS,
    ) -> None:
        """
        Args:
            clock (Callable[[], float]): A monotonic clock in seconds. Injectable so tests do
                not sleep. Defaults to :func:`time.monotonic`.
            max_concurrent_checks (int): Password checks of a login or a setup allowed at once.
                Defaults to ``MAX_CONCURRENT_CHECKS``.
        """
        self._clock = clock
        self._failures: dict[str, _Entry] = {}
        self._lock = threading.Lock()
        self._check_slots = threading.BoundedSemaphore(max_concurrent_checks)

    @contextmanager
    def check_slot(self) -> Iterator[bool]:
        """
        Hold one of the password-check slots, without waiting for it.

        Yields:
            bool: ``True`` when a slot is held for the duration of the block; ``False`` when all
                are taken and the caller must turn the request away.
        """
        acquired = self._check_slots.acquire(blocking=False)
        try:
            yield acquired
        finally:
            if acquired:
                self._check_slots.release()

    def begin_login(self, client_key: str, user_key: str) -> int:
        """
        Check both login limits and, when neither applies, count the attempt, as one step.

        Args:
            client_key (str): The client's key, under the doubling wait.
            user_key (str): The username's key, under the shared window.

        Returns:
            int: The seconds the caller must wait (the attempt is then not counted), or ``0``
                when it may go ahead.
        """
        client, user = _bounded(client_key), _bounded(user_key)
        with self._lock:
            now = self._clock()
            self._forget(now)
            wait = max(self._remaining(client, now), self._remaining(user, now))
            if wait == 0:
                wait = self._make_room((client, user), now)
            if wait == 0:
                self._count(client, now)
                entry = self._failures.pop(user, None)
                self._failures[user] = (
                    entry._replace(attempts=entry.attempts + 1)
                    if entry is not None
                    else _Entry(1, now, windowed=True)
                )
            return math.ceil(wait)

    def finish_login(self, client_key: str, user_key: str) -> None:
        """
        Forget the client's failures and take this attempt back from the username's window.

        Only this attempt: other clients' failures in the window still count, or one good login
        would reopen the shared limit for whoever is guessing.

        Args:
            client_key (str): The client's key.
            user_key (str): The username's key.
        """
        client, user = _bounded(client_key), _bounded(user_key)
        with self._lock:
            self._failures.pop(client, None)
            entry = self._failures.get(user)
            if entry is None:
                return
            if entry.attempts <= 1:
                del self._failures[user]
            else:
                self._failures[user] = entry._replace(attempts=entry.attempts - 1)

    def begin_attempt(self, *keys: str) -> int:
        """
        Check the wait and, when there is none, count this attempt as a failure, as one step.

        The attempt is counted before the password is checked, so parallel attempts see each
        other; a check that then succeeds calls :meth:`clear`.

        Args:
            *keys (str): The keys the attempt counts against.

        Returns:
            int: The seconds the caller must wait (the attempt is then not counted), or ``0``
                when it may go ahead.
        """
        with self._lock:
            wait = self._retry_after(*keys)
            if wait == 0:
                now = self._clock()
                bounded = tuple(map(_bounded, keys))
                wait = math.ceil(self._make_room(bounded, now))
                if wait == 0:
                    for key in bounded:
                        self._count(key, now)
            return wait

    def retry_after(self, *keys: str) -> int:
        """
        Args:
            *keys (str): The keys the attempt counts against.

        Returns:
            int: The seconds the caller must wait, the longest over the keys; ``0`` when it may
                try now.
        """
        with self._lock:
            return self._retry_after(*keys)

    def _retry_after(self, *keys: str) -> int:
        """
        :meth:`retry_after` with the lock already held.

        Args:
            *keys (str): The keys the attempt counts against.

        Returns:
            int: The seconds the caller must wait, the longest over the keys; ``0`` when it may
                try now.
        """
        now = self._clock()
        self._forget(now)
        wait = max((self._remaining(key, now) for key in map(_bounded, keys)), default=0.0)
        return math.ceil(wait)

    def _remaining(self, key: str, now: float) -> float:
        """
        Args:
            key (str): A bounded key.
            now (float): The current time on the throttle's clock.

        Returns:
            float: The seconds this key still has to wait; ``0.0`` when it is unknown or free.
        """
        entry = self._failures.get(key)
        return _entry_wait(entry, now) if entry is not None else 0.0

    def record_failure(self, *keys: str) -> None:
        """
        Args:
            *keys (str): The keys a failed attempt counts against. Not counted when the table is
                full of waiting keys, as :meth:`_make_room` explains.
        """
        with self._lock:
            now = self._clock()
            bounded = tuple(map(_bounded, keys))
            if self._make_room(bounded, now) == 0:
                for key in bounded:
                    self._count(key, now)

    def _count(self, key: str, now: float) -> None:
        """
        Count one failure on a doubling key.

        Args:
            key (str): A bounded key that already has room in the table.
            now (float): The current time on the throttle's clock.
        """
        # Pop and re-insert, so the dict stays ordered by the last failure and the first entry
        # without a wait is the one to drop when the table is full.
        entry = self._failures.pop(key, None)
        self._failures[key] = _Entry((entry.attempts if entry is not None else 0) + 1, now)

    def _make_room(self, keys: Iterable[str], now: float) -> float:
        """
        Free the table for ``keys``, dropping only keys that are not waiting.

        Args:
            keys (Iterable[str]): The bounded keys about to be counted.
            now (float): The current time on the throttle's clock.

        Returns:
            float: ``0.0`` when they fit. Otherwise nothing is dropped and this is the time until
                the first waiting key can leave: the attempt is refused rather than counted
                nowhere, so a full table never means unlimited guesses for a newcomer.
        """
        wanted = set(keys)
        needed = len(self._failures) + len(wanted - self._failures.keys()) - MAX_KEYS
        if needed <= 0:
            return 0.0
        droppable = (
            key
            for key, entry in self._failures.items()
            if key not in wanted and _entry_wait(entry, now) == 0
        )
        victims = list(islice(droppable, needed))
        if len(victims) < needed:
            waits = (_entry_wait(entry, now) for entry in self._failures.values())
            return min((wait for wait in waits if wait > 0), default=float(BUSY_RETRY_S))
        for key in victims:
            del self._failures[key]
        return 0.0

    def clear(self, *keys: str) -> None:
        """
        Args:
            *keys (str): The keys to forget, after a successful check.
        """
        with self._lock:
            for key in map(_bounded, keys):
                self._failures.pop(key, None)

    def _forget(self, now: float) -> None:
        """
        Args:
            now (float): The current time on the throttle's clock.
        """
        stale = [key for key, entry in self._failures.items() if _is_stale(entry, now)]
        for key in stale:
            del self._failures[key]


def _entry_wait(entry: _Entry, now: float) -> float:
    """
    Args:
        entry (_Entry): A table entry.
        now (float): The current time on the throttle's clock.

    Returns:
        float: The seconds it still has to wait; ``0.0`` when it is free to try.
    """
    if entry.windowed:
        if entry.attempts < USER_MAX_ATTEMPTS:
            return 0.0
        return max(0.0, USER_WINDOW_S - (now - entry.stamp))
    if entry.attempts < FREE_ATTEMPTS:
        return 0.0
    delay = min(MAX_DELAY_S, 1 << (entry.attempts - FREE_ATTEMPTS))
    return max(0.0, delay - (now - entry.stamp))


def _is_stale(entry: _Entry, now: float) -> bool:
    """
    Args:
        entry (_Entry): A table entry.
        now (float): The current time on the throttle's clock.

    Returns:
        bool: ``True`` when a window has closed or a doubling key has been quiet long enough.
    """
    if entry.windowed:
        return now - entry.stamp >= USER_WINDOW_S
    return now - entry.stamp > FORGET_AFTER_S


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
