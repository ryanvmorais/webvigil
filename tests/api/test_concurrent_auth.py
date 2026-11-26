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
from webvigil.api.throttle import BUSY_RETRY_S, FREE_ATTEMPTS, LoginThrottle
from webvigil.core.secrets import Secret

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
    # Room for the whole burst, so that only the counting of attempts decides who gets through.
    # ``TestClient.app`` is typed as a bare ASGI app, which declares no ``state``.
    auth_client.app.state.login_throttle = LoginThrottle(  # type: ignore[attr-defined]
        max_concurrent_checks=_PARALLEL
    )
    wrong = {"username": ADMIN["username"], "password": "not-the-password"}
    codes = _together(
        _PARALLEL, lambda _i: auth_client.post("/api/auth/login", json=wrong).status_code
    )
    # Counted before the password is checked: exactly the free attempts go through, the rest wait.
    assert codes == Counter({401: FREE_ATTEMPTS, 429: _PARALLEL - FREE_ATTEMPTS})


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


# ---------------------------------------------------------------------------
# The setup hash and the password-check slots (spec 027, RF-08)
# ---------------------------------------------------------------------------


def _counting_hash(monkeypatch: pytest.MonkeyPatch, during: Callable[[], None]) -> list[int]:
    """
    Args:
        monkeypatch (pytest.MonkeyPatch): Replaces the setup route's hash.
        during (Callable[[], None]): Runs inside each hash, before the real one.

    Returns:
        list[int]: One entry per hash, appended as each one starts.
    """
    real_hash = security.hash_password
    hashed: list[int] = []

    def counted(password: Secret) -> str:
        hashed.append(len(hashed) + 1)
        during()
        return real_hash(password)

    monkeypatch.setattr(setup, "hash_password", counted)
    return hashed


def test_a_setup_without_a_free_check_slot_is_told_to_retry_and_creates_nothing(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every slot taken: 429 with Retry-After, no hash, no account; a free slot then creates it."""
    hashed = _counting_hash(monkeypatch, lambda: None)
    # ``TestClient.app`` is typed as a bare ASGI app, which declares no ``state``.
    state = client.app.state  # type: ignore[attr-defined]
    state.login_throttle = LoginThrottle(max_concurrent_checks=0)

    response = client.post("/api/setup", json=ADMIN)

    assert response.status_code == 429
    assert response.headers["retry-after"] == str(BUSY_RETRY_S)
    assert response.json() == {"detail": "too many password checks in progress: try again shortly"}
    assert hashed == []
    assert client.get("/api/setup").json()["needs_setup"] is True
    # The control: with a slot free, the same request creates the account.
    state.login_throttle = LoginThrottle()
    assert client.post("/api/setup", json=ADMIN).status_code == 201
    assert hashed == [1]


def test_the_setup_hash_runs_while_it_holds_a_check_slot(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With one slot, the hash runs while that slot is taken, and gives it back afterwards."""
    throttle = LoginThrottle(max_concurrent_checks=1)
    # ``TestClient.app`` is typed as a bare ASGI app, which declares no ``state``.
    client.app.state.login_throttle = throttle  # type: ignore[attr-defined]
    held: list[bool] = []

    def check_held() -> None:
        with throttle.check_slot() as admitted:
            held.append(not admitted)

    hashed = _counting_hash(monkeypatch, check_held)

    assert client.post("/api/setup", json=ADMIN).status_code == 201
    assert hashed == [1]
    assert held == [True]
    with throttle.check_slot() as admitted:
        assert admitted  # the slot came back


def test_a_second_setup_gets_409_without_asking_for_a_slot(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An instance already set up answers 409 even while every slot is taken."""
    assert client.post("/api/setup", json=ADMIN).status_code == 201
    hashed = _counting_hash(monkeypatch, lambda: None)
    # ``TestClient.app`` is typed as a bare ASGI app, which declares no ``state``.
    client.app.state.login_throttle = LoginThrottle(  # type: ignore[attr-defined]
        max_concurrent_checks=0
    )

    response = client.post("/api/setup", json={"username": "other", "password": "password456"})

    assert response.status_code == 409
    assert hashed == []
