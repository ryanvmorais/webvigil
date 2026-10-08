"""
Login throttle and the "credentials changed" clock — security audit for 1.0.0.

Pure units: the throttle runs on an injected clock (no sleeping), and ``credentials_changed_at``
is checked against a timestamp without a zone, which is how SQLite hands one back.
"""

from __future__ import annotations

from datetime import UTC, datetime

from webvigil.api.db import User
from webvigil.api.security import credentials_changed_at
from webvigil.api.throttle import FORGET_AFTER_S, FREE_ATTEMPTS, MAX_DELAY_S, LoginThrottle


class _Clock:
    """A clock the test moves by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _fail(throttle: LoginThrottle, times: int, *keys: str) -> None:
    """
    Args:
        throttle (LoginThrottle): The throttle under test.
        times (int): How many failed attempts to record.
        *keys (str): The keys they count against.
    """
    for _ in range(times):
        throttle.record_failure(*keys)


def test_a_few_mistyped_passwords_cost_nothing() -> None:
    """The first ``FREE_ATTEMPTS - 1`` failures leave the caller free to try again at once."""
    throttle = LoginThrottle(clock=_Clock())
    _fail(throttle, FREE_ATTEMPTS - 1, "client:a")
    assert throttle.retry_after("client:a") == 0


def test_the_wait_starts_after_the_free_attempts_and_doubles() -> None:
    """One second after the fifth failure, then two, four, eight: immediately after each."""
    throttle = LoginThrottle(clock=_Clock())
    waits = []
    for _ in range(4):
        _fail(throttle, 1 if waits else FREE_ATTEMPTS, "client:a")
        waits.append(throttle.retry_after("client:a"))
    assert waits == [1, 2, 4, 8]


def test_the_wait_is_capped() -> None:
    """A long run of failures never asks for more than ``MAX_DELAY_S``."""
    throttle = LoginThrottle(clock=_Clock())
    _fail(throttle, 40, "client:a")
    assert throttle.retry_after("client:a") == MAX_DELAY_S


def test_the_wait_runs_down_with_time() -> None:
    """Time spent waiting counts: after the delay has passed the caller may try again."""
    clock = _Clock()
    throttle = LoginThrottle(clock=clock)
    _fail(throttle, FREE_ATTEMPTS + 2, "client:a")  # a 4-second wait
    assert throttle.retry_after("client:a") == 4
    clock.now += 3
    assert throttle.retry_after("client:a") == 1
    clock.now += 1
    assert throttle.retry_after("client:a") == 0


def test_a_success_forgets_the_failures() -> None:
    """``clear`` after a good login resets the count for those keys."""
    throttle = LoginThrottle(clock=_Clock())
    _fail(throttle, 8, "client:a", "user:admin")
    throttle.clear("client:a", "user:admin")
    assert throttle.retry_after("client:a", "user:admin") == 0
    _fail(throttle, 1, "client:a")
    assert throttle.retry_after("client:a") == 0  # back to the free attempts


def test_the_longest_wait_over_the_keys_wins() -> None:
    """An attempt counts against its client and its username: the slower key decides."""
    throttle = LoginThrottle(clock=_Clock())
    _fail(throttle, FREE_ATTEMPTS, "user:admin")  # the username is slowed, this client is not
    assert throttle.retry_after("client:other", "user:admin") == 1
    assert throttle.retry_after("client:other", "user:someone-else") == 0


def test_a_quiet_stretch_forgets_everything() -> None:
    """After ``FORGET_AFTER_S`` without a failure the key starts again, and the table shrinks."""
    clock = _Clock()
    throttle = LoginThrottle(clock=clock)
    _fail(throttle, FREE_ATTEMPTS + 3, "client:a")
    clock.now += FORGET_AFTER_S + 1
    assert throttle.retry_after("client:a") == 0
    assert throttle._failures == {}


def test_credentials_changed_at_reads_a_zoneless_timestamp_as_utc() -> None:
    """SQLite returns naive datetimes; treating them as local time would shift the clock."""
    naive = User(username="admin", password_hash="x", updated_at=datetime(2026, 1, 1, 12, 0, 0))
    aware = User(
        username="admin", password_hash="x", updated_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    )
    expected = int(datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC).timestamp())
    assert credentials_changed_at(naive) == expected
    assert credentials_changed_at(aware) == expected
