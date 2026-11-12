"""
Parallel requests to the unauthenticated routes (GHSA-q373-8m5q-qwww).

The login and setup routes run on a thread pool, so requests really do overlap. Each test slows
the password step down and releases several requests at once, so that, without the fix, all of
them would pass the check before any of them was counted.
"""

from __future__ import annotations

import threading
import time
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from tests.api.conftest import ADMIN
from webvigil.api import security
from webvigil.api.routes import auth, setup
from webvigil.api.throttle import FREE_ATTEMPTS

_PARALLEL = FREE_ATTEMPTS * 2
_SLOW_S = 0.3


def _together(count: int, call: Callable[[int], int]) -> Counter[int]:
    """
    Args:
        count (int): How many calls to start at the same moment.
        call (Callable[[int], int]): Makes request ``i`` and returns its status code.

    Returns:
        Counter[int]: How many requests ended with each status code.
    """
    barrier = threading.Barrier(count)

    def run(i: int) -> int:
        barrier.wait()
        return call(i)

    with ThreadPoolExecutor(max_workers=count) as pool:
        return Counter(pool.map(run, range(count)))


def test_parallel_wrong_passwords_get_no_more_than_the_free_attempts(
    auth_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A burst of parallel guesses is counted as it arrives: the rest of the burst waits."""
    real_verify = security.verify_password

    def slow_verify(password: str, stored_hash: str) -> bool:
        time.sleep(_SLOW_S)
        return real_verify(password, stored_hash)

    monkeypatch.setattr(auth, "verify_password", slow_verify)
    wrong = {"username": ADMIN["username"], "password": "not-the-password"}
    codes = _together(
        _PARALLEL, lambda _i: auth_client.post("/api/auth/login", json=wrong).status_code
    )
    assert codes[401] <= FREE_ATTEMPTS
    assert codes[429] == _PARALLEL - codes[401]


def test_a_right_password_after_a_wrong_one_still_signs_in(auth_client: TestClient) -> None:
    """Counting the attempt up front does not cost the owner: a success clears the count."""
    wrong = {"username": ADMIN["username"], "password": "not-the-password"}
    for _ in range(FREE_ATTEMPTS - 1):
        assert auth_client.post("/api/auth/login", json=wrong).status_code == 401
    for _ in range(FREE_ATTEMPTS):  # each success resets the count, so none is ever throttled
        assert auth_client.post("/api/auth/login", json=ADMIN).status_code == 204


def test_parallel_setups_create_exactly_one_account(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two first-run requests at once: one account, and the other request gets 409."""
    real_hash = security.hash_password

    def slow_hash(password: str) -> str:
        time.sleep(_SLOW_S)
        return real_hash(password)

    monkeypatch.setattr(setup, "hash_password", slow_hash)

    def create(i: int) -> int:
        body = {"username": f"user{i}", "password": ADMIN["password"]}
        return client.post("/api/setup", json=body).status_code

    codes = _together(4, create)
    assert codes == Counter({201: 1, 409: 3})
