"""
The login limits under abuse, and the race between a login and a password change.

Nothing here waits for real time. The throttle runs on a clock the test moves; the wall clock of
the session code is replaced where a test needs two events on the same reading; and an overlap is
built with events and a barrier inside the password step, so the order of the threads is decided
by the test and not by the scheduler. Each test has its own app and database (``conftest.py``), and
a client's address is set through ``TestClient(client=...)``.
"""

from __future__ import annotations

import re
import socket
import threading
from collections import Counter
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlmodel import Session

from tests.api.conftest import ADMIN, FakeOrchestrator
from webvigil.api import security
from webvigil.api.app import create_app
from webvigil.api.client_address import (
    NAME_TTL_S,
    IPAddress,
    TrustedProxies,
    client_address,
    parse_address,
)
from webvigil.api.config import WebConfig
from webvigil.api.db import User, session_scope, utcnow
from webvigil.api.routes import auth
from webvigil.api.security import SESSION_COOKIE, create_token, store_password_hash
from webvigil.api.throttle import (
    BUSY_RETRY_S,
    FREE_ATTEMPTS,
    MAX_CONCURRENT_CHECKS,
    MAX_KEYS,
    USER_MAX_ATTEMPTS,
    USER_WINDOW_S,
    LoginThrottle,
    _Entry,
)

_PROXY = "203.0.113.1"
_OTHER_PROXY = "203.0.113.2"
_WRONG = {"username": ADMIN["username"], "password": "not-the-password"}
_NEW_PASSWORD = "a-brand-new-password"
_WAIT_S = 10  # how long a blocked thread may take before the test fails instead of hanging


class _Clock:
    """A clock the test moves by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> _Clock:
    """
    Returns:
        _Clock: The clock of the app's throttle.
    """
    return _Clock()


@pytest.fixture
def app(web_config: WebConfig, clock: _Clock) -> Iterator[FastAPI]:
    """
    Args:
        web_config (WebConfig): The per-test configuration.
        clock (_Clock): Drives the throttle.

    Yields:
        FastAPI: A running app with its account created, trusting ``_PROXY`` only.
    """
    config = web_config.model_copy(update={"trusted_proxies": [_PROXY]})
    application = create_app(config, orchestrator_factory=FakeOrchestrator)
    with TestClient(application) as bootstrap:
        assert bootstrap.post("/api/setup", json=ADMIN).status_code == 201
        application.state.login_throttle = LoginThrottle(clock=clock)
        yield application


def _from(application: FastAPI, address: str) -> TestClient:
    """
    Args:
        application (FastAPI): The running app.
        address (str): The address of the connection.

    Returns:
        TestClient: A client connecting from ``address``, with its own cookie jar.
    """
    return TestClient(application, client=(address, 4000))


def _throttle(application: FastAPI) -> LoginThrottle:
    """
    Args:
        application (FastAPI): The running app.

    Returns:
        LoginThrottle: Its login throttle.
    """
    throttle: LoginThrottle = application.state.login_throttle
    return throttle


# ---------------------------------------------------------------------------
# A login racing a password change
# ---------------------------------------------------------------------------


def test_a_change_that_lands_during_the_check_ends_the_session(app: FastAPI) -> None:
    """A login that verified the old password gets a cookie the finished change has revoked."""
    owner = _from(app, "192.0.2.10")
    assert owner.post("/api/auth/login", json=ADMIN).status_code == 204
    racing = _from(app, "192.0.2.11")
    in_check, finish_check = threading.Event(), threading.Event()
    real_verify = auth.verify_password

    def held_verify(password: str, hashed: str) -> bool:
        if not in_check.is_set():  # only the racing login, which arrives first
            in_check.set()
            assert finish_check.wait(_WAIT_S)
        return real_verify(password, hashed)

    with pytest.MonkeyPatch.context() as patch, ThreadPoolExecutor(max_workers=1) as pool:
        patch.setattr(auth, "verify_password", held_verify)
        login = pool.submit(racing.post, "/api/auth/login", json=ADMIN)
        assert in_check.wait(_WAIT_S)
        changed = owner.post(
            "/api/auth/password",
            json={"current_password": ADMIN["password"], "new_password": _NEW_PASSWORD},
        )
        finish_check.set()
        assert changed.status_code == 204
        assert login.result(_WAIT_S).status_code == 204  # it did verify the password it was given

    assert SESSION_COOKIE in racing.cookies
    assert racing.get("/api/auth/me").status_code == 401
    assert owner.get("/api/auth/me").status_code == 200  # the session that changed it stays


def test_a_login_after_a_change_works_on_the_same_clock_reading(
    app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the clock standing still, a login with the new password is not taken for an old one."""
    frozen = utcnow()  # after the setup, and not ahead of the real clock
    monkeypatch.setattr(security, "utcnow", lambda: frozen)
    monkeypatch.setattr(auth, "utcnow", lambda: frozen)
    owner = _from(app, "192.0.2.10")
    assert owner.post("/api/auth/login", json=ADMIN).status_code == 204
    changed = owner.post(
        "/api/auth/password",
        json={"current_password": ADMIN["password"], "new_password": _NEW_PASSWORD},
    )
    assert changed.status_code == 204
    fresh = _from(app, "192.0.2.11")
    body = {"username": ADMIN["username"], "password": _NEW_PASSWORD}
    assert fresh.post("/api/auth/login", json=body).status_code == 204
    assert fresh.get("/api/auth/me").status_code == 200


def test_a_token_from_the_last_reading_before_the_change_is_ended(
    app: FastAPI, web_config: WebConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A clock too coarse to separate the two cannot keep the older token alive."""
    frozen = utcnow()  # after the setup, and not ahead of the real clock
    monkeypatch.setattr(security, "utcnow", lambda: frozen)
    monkeypatch.setattr(auth, "utcnow", lambda: frozen)
    owner = _from(app, "192.0.2.10")
    assert owner.post("/api/auth/login", json=ADMIN).status_code == 204
    older = _from(app, "192.0.2.11")
    assert web_config.session_secret is not None
    token = create_token(1, web_config.session_secret, 12, issued_at=frozen)
    older.cookies.set(SESSION_COOKIE, token)
    assert older.get("/api/auth/me").status_code == 200  # valid until the change
    changed = owner.post(
        "/api/auth/password",
        json={"current_password": ADMIN["password"], "new_password": _NEW_PASSWORD},
    )
    assert changed.status_code == 204
    assert older.get("/api/auth/me").status_code == 401


def test_the_change_is_stamped_after_the_new_hash_is_visible(
    app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reader sees the old hash until the first commit, so the stamp comes from after it."""
    before_commit = utcnow() - timedelta(minutes=2)
    after_commit = before_commit + timedelta(seconds=10)
    readings = iter([before_commit, after_commit])
    monkeypatch.setattr(security, "utcnow", lambda: next(readings))
    with Session(app.state.engine) as session:
        user = session.get(User, 1)
        assert user is not None
        changed_at = store_password_hash(session, 1, "new-hash", expected_hash=user.password_hash)
    assert changed_at == after_commit + timedelta(microseconds=1)
    with Session(app.state.engine) as session:
        stored = session.get(User, 1)
        assert stored is not None
        assert stored.password_hash == "new-hash"
        assert security.credentials_stamp(stored) == changed_at


def test_a_clock_that_steps_back_does_not_stamp_the_change_before_its_write(
    app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A later reading behind the first one (a clock set back) still stamps after the swap."""
    swapped = utcnow() - timedelta(minutes=2)
    readings = iter([swapped, swapped - timedelta(seconds=10)])
    monkeypatch.setattr(security, "utcnow", lambda: next(readings))
    with Session(app.state.engine) as session:
        changed_at = store_password_hash(session, 1, "new-hash")
    assert changed_at == swapped + timedelta(microseconds=1)


def test_the_cookie_of_a_change_is_issued_at_the_stored_stamp(app: FastAPI) -> None:
    """The session that changed the password is exactly as new as the change, not newer."""
    owner = _from(app, "192.0.2.10")
    assert owner.post("/api/auth/login", json=ADMIN).status_code == 204
    changed = owner.post(
        "/api/auth/password",
        json={"current_password": ADMIN["password"], "new_password": _NEW_PASSWORD},
    )
    assert changed.status_code == 204
    claims = security.decode_token(str(owner.cookies[SESSION_COOKIE]), app.state.session_secret)
    with Session(app.state.engine) as session:
        stored = session.get(User, 1)
        assert stored is not None
    assert claims is not None
    assert claims.issued_at == security.credentials_changed_at(stored)


def test_a_login_long_after_the_last_change_gets_a_session_that_works(app: FastAPI) -> None:
    """The token counts from the login, not from a change older than the session lifetime."""
    ttl = app.state.config.session_ttl_hours
    with Session(app.state.engine) as session:
        user = session.get(User, 1)
        assert user is not None
        user.updated_at = utcnow() - timedelta(hours=ttl + 1)
        session.add(user)
        session.commit()
    client = _from(app, "192.0.2.10")
    assert client.post("/api/auth/login", json=ADMIN).status_code == 204
    assert client.get("/api/auth/me").status_code == 200


def test_of_two_parallel_changes_exactly_one_is_stored(app: FastAPI) -> None:
    """Both verified the same password; the second write finds another hash and gets 409."""
    first = _from(app, "192.0.2.10")
    assert first.post("/api/auth/login", json=ADMIN).status_code == 204
    second = _from(app, "192.0.2.11")
    second.cookies.set(SESSION_COOKIE, str(first.cookies[SESSION_COOKIE]))
    both_verified = threading.Barrier(2, timeout=_WAIT_S)
    real_hash = auth.hash_password

    def held_hash(password: str) -> str:
        both_verified.wait()
        return real_hash(password)

    passwords = ["first-new-password", "second-new-password"]

    def change(pair: tuple[TestClient, str]) -> int:
        body = {"current_password": ADMIN["password"], "new_password": pair[1]}
        return pair[0].post("/api/auth/password", json=body).status_code

    with pytest.MonkeyPatch.context() as patch, ThreadPoolExecutor(max_workers=2) as pool:
        patch.setattr(auth, "hash_password", held_hash)
        codes = list(pool.map(change, zip((first, second), passwords, strict=True)))

    assert Counter(codes) == Counter({204: 1, 409: 1})
    winner = passwords[codes.index(204)]
    loser = passwords[codes.index(409)]
    probe = _from(app, "192.0.2.12")
    name = ADMIN["username"]
    assert (
        probe.post("/api/auth/login", json={"username": name, "password": loser}).status_code == 401
    )
    assert (
        probe.post("/api/auth/login", json={"username": name, "password": winner}).status_code
        == 204
    )


def test_a_reset_between_the_two_writes_leaves_the_change_without_a_token(
    app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Held between the change's two commits, a reset wins: 409, no cookie, the old session ends."""
    client = _from(app, "192.0.2.40")
    assert client.post("/api/auth/login", json=ADMIN).status_code == 204
    first_write_done = threading.Event()
    reset_done = threading.Event()
    readings: list[None] = []
    real_now = security.utcnow

    def held_now() -> datetime:
        readings.append(None)
        if len(readings) == 2:  # the reading the change takes between its two commits
            first_write_done.set()
            assert reset_done.wait(_WAIT_S)
        return real_now()

    def reset() -> datetime | None:
        assert first_write_done.wait(_WAIT_S)
        try:
            with Session(app.state.engine) as session:
                return store_password_hash(session, 1, "reset-hash")
        finally:
            reset_done.set()

    monkeypatch.setattr(security, "utcnow", held_now)
    body = {"current_password": ADMIN["password"], "new_password": "changed-password"}
    with ThreadPoolExecutor(max_workers=1) as pool:
        racing = pool.submit(reset)
        answer = client.post("/api/auth/password", json=body)
        reset_stamp = racing.result(timeout=_WAIT_S)

    assert reset_stamp is not None  # the control: the reset did land in the gap
    assert answer.status_code == 409
    assert answer.json()["detail"] == "the password was changed by another request"
    assert "set-cookie" not in answer.headers
    with Session(app.state.engine) as session:
        stored = session.get(User, 1)
        assert stored is not None
        assert stored.password_hash == "reset-hash"
        assert security.credentials_stamp(stored) == reset_stamp
    assert client.get("/api/auth/me").status_code == 401


def test_reset_password_goes_through_the_same_stamp(
    web_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without an expected hash the write is unconditional, and it is stamped after the commit."""
    with session_scope(web_engine) as session:
        session.add(User(username="admin", password_hash="old-hash"))
    before_commit = utcnow() - timedelta(minutes=2)
    readings = iter([before_commit, before_commit])
    monkeypatch.setattr(security, "utcnow", lambda: next(readings))
    with Session(web_engine) as session:
        changed_at = store_password_hash(session, 1, "reset-hash")
    assert changed_at == before_commit + timedelta(microseconds=1)
    with Session(web_engine) as session:
        stored = session.get(User, 1)
        assert stored is not None and stored.password_hash == "reset-hash"


# ---------------------------------------------------------------------------
# How many Argon2 checks run at once
# ---------------------------------------------------------------------------


def test_only_the_limit_of_checks_runs_at_once(app: FastAPI) -> None:
    """The excess is answered at once, the same for a real and a made-up name, and not counted."""
    entered = threading.Semaphore(0)
    finish = threading.Event()
    calls: list[str] = []
    real_verify = auth.verify_password

    def held_verify(password: str, hashed: str) -> bool:
        calls.append(hashed)
        entered.release()
        assert finish.wait(_WAIT_S)
        return real_verify(password, hashed)

    holders = [_from(app, f"198.51.100.{i}") for i in range(1, MAX_CONCURRENT_CHECKS + 1)]
    with (
        pytest.MonkeyPatch.context() as patch,
        ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CHECKS) as pool,
    ):
        patch.setattr(auth, "verify_password", held_verify)
        running = [pool.submit(c.post, "/api/auth/login", json=_WRONG) for c in holders]
        for _ in holders:
            assert entered.acquire(timeout=_WAIT_S)

        excess = _from(app, "192.0.2.99")
        real_name = excess.post("/api/auth/login", json=_WRONG)
        made_up = excess.post(
            "/api/auth/login", json={"username": "nobody-here", "password": "a-guess"}
        )
        assert len(calls) == MAX_CONCURRENT_CHECKS  # the excess never reached Argon2
        finish.set()
        assert [future.result(_WAIT_S).status_code for future in running] == [401] * len(holders)

    assert real_name.status_code == made_up.status_code == 429
    assert real_name.headers["retry-after"] == made_up.headers["retry-after"] == str(BUSY_RETRY_S)
    assert real_name.json() == made_up.json()
    assert "client:192.0.2.99" not in _throttle(app)._failures
    # Every slot came back: a full set of new checks is admitted.
    assert excess.post("/api/auth/login", json=_WRONG).status_code == 401


def test_a_refused_login_gives_its_slot_back(app: FastAPI, clock: _Clock) -> None:
    """Being told to wait holds no slot, however many times it happens."""
    client = _from(app, "192.0.2.10")
    for _ in range(FREE_ATTEMPTS):
        assert client.post("/api/auth/login", json=_WRONG).status_code == 401
    for _ in range(MAX_CONCURRENT_CHECKS + 1):
        assert client.post("/api/auth/login", json=_WRONG).status_code == 429
    clock.now += 1
    assert client.post("/api/auth/login", json=_WRONG).status_code == 401


# ---------------------------------------------------------------------------
# The bounded table
# ---------------------------------------------------------------------------


def _full_of_waiters(clock: _Clock) -> LoginThrottle:
    """
    Args:
        clock (_Clock): The throttle's clock.

    Returns:
        LoginThrottle: A throttle whose table holds ``MAX_KEYS`` keys, each one second from free.
    """
    throttle = LoginThrottle(clock=clock)
    throttle._failures = {
        f"client:{index}": _Entry(FREE_ATTEMPTS, clock.now) for index in range(MAX_KEYS)
    }
    return throttle


def test_a_waiting_key_survives_a_full_table_of_new_keys(clock: _Clock) -> None:
    """New keys push out what is not waiting, even though the waiting key is the oldest."""
    throttle = LoginThrottle(clock=clock)
    for _ in range(FREE_ATTEMPTS + 3):
        throttle.record_failure("client:waiting")
    throttle.record_failure("client:idle")
    expected = throttle.retry_after("client:waiting")
    assert expected == 8
    for index in range(MAX_KEYS):
        throttle.record_failure(f"user:new-{index}")
    assert len(throttle._failures) == MAX_KEYS
    assert "client:idle" not in throttle._failures  # the control: the new keys did evict
    assert throttle.retry_after("client:waiting") == expected


def test_a_table_full_of_waiters_refuses_a_new_key_until_the_first_wait_ends(
    clock: _Clock,
) -> None:
    """Nobody waiting gets their attempts back, and a newcomer is not left uncounted."""
    throttle = _full_of_waiters(clock)
    assert throttle.begin_login("client:new", "user:new") == 1
    assert throttle.begin_attempt("password:user:1") == 1
    assert "client:new" not in throttle._failures
    assert "user:new" not in throttle._failures
    assert "password:user:1" not in throttle._failures
    assert len(throttle._failures) == MAX_KEYS
    assert throttle.retry_after("client:0") == 1  # still waiting

    clock.now += 1  # every wait has ended, so each of them may now leave
    assert throttle.begin_login("client:new", "user:new") == 0
    assert "client:new" in throttle._failures and "user:new" in throttle._failures
    assert len(throttle._failures) == MAX_KEYS


def test_a_full_table_waits_for_the_soonest_key(clock: _Clock) -> None:
    """The newcomer is told the shortest of the remaining waits, not the longest."""
    throttle = _full_of_waiters(clock)
    throttle._failures = {
        key: _Entry(FREE_ATTEMPTS + 3, clock.now) for key in throttle._failures
    }  # all eight seconds away
    throttle._failures["client:0"] = _Entry(FREE_ATTEMPTS + 2, clock.now)  # four seconds away
    assert throttle.begin_attempt("client:new") == 4


def test_a_key_already_in_a_full_table_is_still_counted(clock: _Clock) -> None:
    """A waiter whose wait ended needs no new room, so a full table does not refuse it."""
    throttle = _full_of_waiters(clock)
    throttle._failures = {key: _Entry(FREE_ATTEMPTS + 3, clock.now) for key in throttle._failures}
    throttle._failures["client:0"] = _Entry(FREE_ATTEMPTS, clock.now)
    clock.now += 1  # only this key's wait has ended: nothing else could leave to make room
    assert throttle.begin_attempt("client:0") == 0
    assert throttle._failures["client:0"].attempts == FREE_ATTEMPTS + 1
    assert len(throttle._failures) == MAX_KEYS


def test_a_key_about_to_be_counted_is_not_dropped_to_make_room(clock: _Clock) -> None:
    """The only key free to leave is the client's own: dropping it would reset its count."""
    throttle = _full_of_waiters(clock)
    throttle._failures = {key: _Entry(FREE_ATTEMPTS + 3, clock.now) for key in throttle._failures}
    throttle._failures["client:0"] = _Entry(FREE_ATTEMPTS, clock.now)
    clock.now += 1  # only this key's wait has ended, and the username needs a new entry
    assert throttle.begin_login("client:0", "user:new") > 0
    assert throttle._failures["client:0"].attempts == FREE_ATTEMPTS
    assert "user:new" not in throttle._failures


# ---------------------------------------------------------------------------
# One client does not delay another
# ---------------------------------------------------------------------------


def _login_answer(client: TestClient, username: str) -> tuple[int, str, str | None]:
    """
    Args:
        client (TestClient): Who logs in.
        username (str): The username, with a wrong password.

    Returns:
        tuple[int, str, str | None]: The status, the detail and ``Retry-After``.
    """
    answer = client.post(
        "/api/auth/login", json={"username": username, "password": "not-the-password"}
    )
    return answer.status_code, answer.json()["detail"], answer.headers.get("retry-after")


def test_a_waiting_client_is_answered_without_taking_a_check_slot(
    app: FastAPI, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same answer for a real and an unknown username, and no slot asked for until it ends."""
    client = _from(app, "192.0.2.30")
    for _ in range(FREE_ATTEMPTS):
        assert _login_answer(client, ADMIN["username"])[0] == 401
    throttle = _throttle(app)
    slots: list[None] = []
    real_slot = throttle.check_slot

    def counted_slot() -> Any:
        slots.append(None)
        return real_slot()

    monkeypatch.setattr(throttle, "check_slot", counted_slot)
    waiting = (429, "too many failed logins: try again later", "1")

    assert _login_answer(client, ADMIN["username"]) == waiting
    assert _login_answer(client, "nobody-here") == waiting
    assert slots == []

    clock.now += 1  # the control: once the wait ends, the same client asks for a slot again
    assert _login_answer(client, ADMIN["username"])[0] == 401
    assert len(slots) == 1


def test_a_waiting_client_hears_its_wait_when_every_slot_is_taken(
    app: FastAPI,
) -> None:
    """Busy slots do not change the answer: the wait it must serve is what it is told."""
    client = _from(app, "192.0.2.31")
    for _ in range(FREE_ATTEMPTS):
        assert _login_answer(client, ADMIN["username"])[0] == 401
    throttle = _throttle(app)
    held = [throttle.check_slot() for _ in range(MAX_CONCURRENT_CHECKS)]
    assert all(slot.__enter__() for slot in held)  # the path under test: nothing is free
    try:
        assert _login_answer(client, ADMIN["username"]) == (
            429,
            "too many failed logins: try again later",
            "1",
        )
        other = _from(app, "192.0.2.32")  # the control: a client not waiting finds no slot
        assert _login_answer(other, ADMIN["username"]) == (
            429,
            "too many logins in progress: try again shortly",
            "1",
        )
    finally:
        for slot in held:
            slot.__exit__(None, None, None)


def test_a_client_that_fails_does_not_delay_another(app: FastAPI) -> None:
    """The one guessing is stopped; the owner, elsewhere, signs in."""
    guesser = _from(app, "192.0.2.66")
    for _ in range(FREE_ATTEMPTS):
        assert guesser.post("/api/auth/login", json=_WRONG).status_code == 401
    barred = guesser.post("/api/auth/login", json=ADMIN)
    assert barred.status_code == 429  # the control: the right password does not help it
    assert barred.headers["retry-after"] == "1"
    assert _from(app, "192.0.2.10").post("/api/auth/login", json=ADMIN).status_code == 204


def test_clients_behind_the_trusted_proxy_are_told_apart(app: FastAPI) -> None:
    """Through the proxy, the wait belongs to the forwarded client and not to the proxy."""
    proxy = _from(app, _PROXY)
    guesser, owner = {"X-Forwarded-For": "198.51.100.1"}, {"X-Forwarded-For": "198.51.100.2"}
    for _ in range(FREE_ATTEMPTS):
        assert proxy.post("/api/auth/login", json=_WRONG, headers=guesser).status_code == 401
    assert proxy.post("/api/auth/login", json=ADMIN, headers=guesser).status_code == 429
    assert proxy.post("/api/auth/login", json=ADMIN, headers=owner).status_code == 204


def test_a_repeated_header_is_read_as_one_list_of_hops(app: FastAPI) -> None:
    """Two header lines are one list: the last line holds the hop the proxy appended."""
    proxy = _from(app, _PROXY)
    repeated = [("X-Forwarded-For", "198.51.100.1"), ("X-Forwarded-For", "198.51.100.2")]
    for _ in range(FREE_ATTEMPTS):
        assert proxy.post("/api/auth/login", json=_WRONG, headers=repeated).status_code == 401
    alone = {"X-Forwarded-For": "198.51.100.2"}
    assert proxy.post("/api/auth/login", json=ADMIN, headers=alone).status_code == 429
    other = {"X-Forwarded-For": "198.51.100.1"}
    assert proxy.post("/api/auth/login", json=ADMIN, headers=other).status_code == 204


def test_a_good_login_gives_its_attempt_back(app: FastAPI) -> None:
    """More good logins than the shared limit allows: none of them counts against it."""
    client = _from(app, "192.0.2.10")
    for _ in range(USER_MAX_ATTEMPTS + 1):
        assert client.post("/api/auth/login", json=ADMIN).status_code == 204
    assert "user:admin" not in _throttle(app)._failures


# ---------------------------------------------------------------------------
# Forwarding headers
# ---------------------------------------------------------------------------


def _keys_after_one_failure(
    application: FastAPI, address: str, headers: dict[str, str]
) -> set[str]:
    """
    Args:
        application (FastAPI): The running app.
        address (str): The address of the connection.
        headers (dict[str, str]): The headers of the failed login.

    Returns:
        set[str]: The ``client:`` keys in the throttle after that one attempt.
    """
    response = _from(application, address).post("/api/auth/login", json=_WRONG, headers=headers)
    assert response.status_code == 401
    return {key for key in _throttle(application)._failures if key.startswith("client:")}


@pytest.mark.parametrize(
    "headers",
    [
        {"X-Forwarded-For": "198.51.100.7"},
        {"X-Forwarded-Host": "localhost:3000"},
        {"X-Forwarded-For": "198.51.100.7", "X-Forwarded-Host": "localhost:3000"},
    ],
)
def test_forged_headers_from_an_untrusted_peer_do_not_change_the_key(
    app: FastAPI, headers: dict[str, str]
) -> None:
    """Only the connection counts when the peer is not a trusted proxy."""
    assert _keys_after_one_failure(app, "192.0.2.50", headers) == {"client:192.0.2.50"}


def test_a_trusted_proxy_changes_the_key_with_x_forwarded_for(app: FastAPI) -> None:
    """The same header from the proxy names the client: the positive control of the test above."""
    headers = {"X-Forwarded-For": "198.51.100.7"}
    assert _keys_after_one_failure(app, _PROXY, headers) == {"client:198.51.100.7"}


def test_a_trusted_proxy_keeps_its_own_key_with_only_x_forwarded_host(app: FastAPI) -> None:
    """``X-Forwarded-Host`` says where the request was going, not who sent it."""
    headers = {"X-Forwarded-Host": "localhost:3000"}
    assert _keys_after_one_failure(app, _PROXY, headers) == {f"client:{_PROXY}"}


def test_a_client_cannot_escape_its_wait_through_the_proxy_by_rotating_a_forged_hop(
    app: FastAPI,
) -> None:
    """A hop the client wrote sits left of the one the proxy appended, and is never reached."""
    proxy = _from(app, _PROXY)
    for index in range(FREE_ATTEMPTS):
        headers = {"X-Forwarded-For": f"198.51.100.{index}, 192.0.2.66"}
        assert proxy.post("/api/auth/login", json=_WRONG, headers=headers).status_code == 401
    rotated = {"X-Forwarded-For": "198.51.100.200, 192.0.2.66"}
    assert proxy.post("/api/auth/login", json=_WRONG, headers=rotated).status_code == 429


@pytest.mark.parametrize(
    ("peer", "forwarded", "expected"),
    [
        ("192.0.2.1", [], "192.0.2.1"),
        ("192.0.2.1", ["198.51.100.7"], "192.0.2.1"),  # an untrusted peer: the header is ignored
        (_PROXY, [], _PROXY),
        (_PROXY, ["198.51.100.7"], "198.51.100.7"),
        (_PROXY, ["198.51.100.9, 198.51.100.7"], "198.51.100.7"),  # the left part is the client's
        (_PROXY, [f"198.51.100.9, 198.51.100.7, {_OTHER_PROXY}"], "198.51.100.7"),
        (_PROXY, ["198.51.100.9", f"198.51.100.7, {_OTHER_PROXY}"], "198.51.100.7"),
        (_PROXY, ["198.51.100.7", _OTHER_PROXY], "198.51.100.7"),  # the walk crosses header lines
        (_PROXY, [f"{_OTHER_PROXY}, {_PROXY}"], _OTHER_PROXY),  # every hop is a proxy
        (_PROXY, ["not-an-address"], _PROXY),  # garbage cannot mint a key
        (_PROXY, [f"not-an-address, {_OTHER_PROXY}"], _OTHER_PROXY),
        (_PROXY, ["198.51.100.9, not-an-address"], _PROXY),  # nothing left of it is believed
        (f"::ffff:{_PROXY}", ["198.51.100.7"], "198.51.100.7"),  # a dual-stack socket's form
        (_PROXY, ["::ffff:198.51.100.7"], "198.51.100.7"),
        ("2001:db8:1:2:3:4:5:6", [], "2001:db8:1:2::/64"),
        (_PROXY, ["2001:db8:1:2:aaaa::1"], "2001:db8:1:2::/64"),
        ("testclient", ["198.51.100.7"], "testclient"),  # no address to compare with a proxy
        (None, ["198.51.100.7"], "unknown"),
    ],
)
def test_the_client_is_the_first_untrusted_hop_from_the_right(
    peer: str | None, forwarded: list[str], expected: str
) -> None:
    """The walk from the connection to the left, hop by hop."""
    trusted = TrustedProxies([_PROXY, _OTHER_PROXY])
    assert client_address(peer, forwarded, trusted) == expected


def test_a_cidr_entry_covers_its_network() -> None:
    """A network is trusted as a whole, and only inside its bounds."""
    trusted = TrustedProxies(["10.1.2.0/24"])
    assert client_address("10.1.2.200", ["198.51.100.7"], trusted) == "198.51.100.7"
    assert client_address("10.1.3.1", ["198.51.100.7"], trusted) == "10.1.3.1"


def _address(text: str) -> IPAddress:
    """
    Args:
        text (str): A valid address.

    Returns:
        IPAddress: It, parsed.
    """
    parsed = parse_address(text)
    assert parsed is not None
    return parsed


def _resolver(
    answers: dict[str, list[str]],
) -> tuple[Callable[[str], frozenset[IPAddress]], list[str]]:
    """
    Args:
        answers (dict[str, list[str]]): The addresses of each name, changed by the test later.

    Returns:
        tuple[Callable[[str], frozenset[IPAddress]], list[str]]: A resolver with no DNS, and the
            list of the names it was asked for.
    """
    asked: list[str] = []

    def resolve(name: str) -> frozenset[IPAddress]:
        asked.append(name)
        return frozenset(_address(text) for text in answers.get(name, []))

    return resolve, asked


def test_a_named_proxy_is_recognized_and_resolved_again_after_its_ttl(clock: _Clock) -> None:
    """A recreated container gets a new address: the old one stops being trusted."""
    answers = {"web": ["172.18.0.3"]}
    resolve, asked = _resolver(answers)
    trusted = TrustedProxies(["web"], resolve=resolve, clock=clock)
    assert _address("172.18.0.3") in trusted
    assert _address("172.18.0.4") not in trusted
    assert asked == ["web"]  # the second question was answered from memory

    answers["web"] = ["172.18.0.4"]
    clock.now += NAME_TTL_S - 1
    assert _address("172.18.0.3") in trusted  # not yet expired
    clock.now += 1
    assert _address("172.18.0.4") in trusted
    assert _address("172.18.0.3") not in trusted
    assert asked == ["web", "web"]


def test_a_name_that_does_not_resolve_trusts_nobody(clock: _Clock) -> None:
    """In Compose the API starts first: until the dashboard exists, its name vouches for no one."""
    answers: dict[str, list[str]] = {}
    resolve, _asked = _resolver(answers)
    trusted = TrustedProxies(["web"], resolve=resolve, clock=clock)
    assert client_address("172.18.0.3", ["198.51.100.7"], trusted) == "172.18.0.3"
    answers["web"] = ["172.18.0.3"]
    clock.now += NAME_TTL_S
    assert client_address("172.18.0.3", ["198.51.100.7"], trusted) == "198.51.100.7"


def test_a_request_without_the_header_needs_no_lookup(clock: _Clock) -> None:
    """Without a hop to believe, the proxy's name is not resolved at all."""
    resolve, asked = _resolver({"web": ["172.18.0.3"]})
    trusted = TrustedProxies(["web"], resolve=resolve, clock=clock)
    assert client_address("172.18.0.3", [], trusted) == "172.18.0.3"
    assert asked == []


# ---------------------------------------------------------------------------
# The shared limit per username
# ---------------------------------------------------------------------------


def test_the_shared_limit_stops_at_the_exact_threshold(clock: _Clock) -> None:
    """The last allowed attempt goes through; one more, from a new client, waits out the window."""
    throttle = LoginThrottle(clock=clock)
    for index in range(USER_MAX_ATTEMPTS):
        assert throttle.begin_login(f"client:{index}", "user:admin") == 0
    assert throttle.begin_login("client:one-above", "user:admin") == USER_WINDOW_S
    assert "client:one-above" not in throttle._failures  # a refused attempt is not counted
    assert throttle.begin_login("client:one-above", "user:someone-else") == 0  # that name only

    clock.now += USER_WINDOW_S - 1
    assert throttle.begin_login("client:one-above", "user:admin") == 1
    clock.now += 1
    assert throttle.begin_login("client:one-above", "user:admin") == 0
    assert throttle._failures["user:admin"].attempts == 1  # a new window


def test_the_shared_limit_answers_through_the_route(app: FastAPI, clock: _Clock) -> None:
    """Spread over many addresses, the guesses are contained with a 429 and ``Retry-After``."""
    for index in range(USER_MAX_ATTEMPTS):
        client = _from(app, f"198.51.100.{index + 1}")
        assert client.post("/api/auth/login", json=_WRONG).status_code == 401
    blocked = _from(app, "192.0.2.200").post("/api/auth/login", json=ADMIN)
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == str(USER_WINDOW_S)
    clock.now += USER_WINDOW_S
    assert _from(app, "192.0.2.200").post("/api/auth/login", json=ADMIN).status_code == 204


def test_one_client_alone_never_reaches_the_shared_limit(clock: _Clock) -> None:
    """Retrying the moment each wait ends, a client peaks at nine attempts in a window."""
    throttle = LoginThrottle(clock=clock)
    peak = 0
    for _ in range(4 * 900):  # a quarter-second step, for a quarter of an hour
        while throttle.begin_login("client:alone", "user:admin") == 0:
            peak = max(peak, throttle._failures["user:admin"].attempts)
        clock.now += 0.25
    assert peak == 9
    assert peak < USER_MAX_ATTEMPTS


def test_a_good_login_takes_back_only_its_own_attempt(clock: _Clock) -> None:
    """Other clients' failures stay in the window, or one login would reopen it for them."""
    throttle = LoginThrottle(clock=clock)
    for index in range(3):
        assert throttle.begin_login(f"client:{index}", "user:admin") == 0
    throttle.finish_login("client:0", "user:admin")
    assert "client:0" not in throttle._failures
    assert throttle._failures["user:admin"].attempts == 2
    assert throttle._failures["client:1"].attempts == 1


def test_finishing_a_login_whose_window_is_gone_is_harmless(clock: _Clock) -> None:
    """The window may have closed during the check: a key that is gone loses nothing."""
    throttle = LoginThrottle(clock=clock)
    assert throttle.begin_login("client:a", "user:admin") == 0
    throttle.clear("user:admin")
    throttle.finish_login("client:a", "user:admin")
    assert throttle._failures == {}


def test_the_password_change_keeps_its_own_limit_per_user(auth_client: TestClient) -> None:
    """Moving the login limit to the client leaves the re-check limited by account."""
    wrong = {"current_password": "not-the-password", "new_password": _NEW_PASSWORD}
    for _ in range(FREE_ATTEMPTS):
        assert auth_client.post("/api/auth/password", json=wrong).status_code == 403
    cookie = str(auth_client.cookies[SESSION_COOKIE])
    elsewhere = TestClient(auth_client.app, client=("198.51.100.9", 4000))
    elsewhere.cookies.set(SESSION_COOKIE, cookie)
    assert elsewhere.post("/api/auth/password", json=wrong).status_code == 429


# ---------------------------------------------------------------------------
# Resolving a proxy's name, and the Compose wiring
# ---------------------------------------------------------------------------


def test_a_name_resolves_through_the_system_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both address families are read, a mapped IPv4 unwrapped, and the name is what is asked."""
    asked: list[str] = []

    def fake_getaddrinfo(name: str, *_args: object, **_kwargs: object) -> list[object]:
        asked.append(name)
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.18.0.3", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:172.18.0.4", 0, 0, 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fd00::5", 0, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    trusted = TrustedProxies(["web"])
    assert _address("172.18.0.3") in trusted
    assert _address("172.18.0.4") in trusted
    assert _address("fd00::5") in trusted
    assert _address("172.18.0.5") not in trusted
    assert asked == ["web"]


@pytest.mark.parametrize(
    "error",
    [socket.gaierror("no such name"), UnicodeError("label too long")],
    ids=["unknown-name", "name-that-cannot-be-encoded"],
)
def test_a_failed_lookup_trusts_nobody(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    """A resolver error is the same as no address, and does not reach the login."""

    def failing_getaddrinfo(*_args: object, **_kwargs: object) -> list[object]:
        raise error

    monkeypatch.setattr(socket, "getaddrinfo", failing_getaddrinfo)
    assert client_address("172.18.0.3", ["198.51.100.7"], TrustedProxies(["web"])) == "172.18.0.3"


def test_compose_trusts_the_dashboard_and_its_image_reports_the_connection() -> None:
    """Trusting the dashboard is only safe while its image appends the real connection."""
    root = Path(__file__).resolve().parents[2]
    compose = (root / "docker-compose.yml").read_text("utf-8")
    assert re.search(r"^\s+WEBVIGIL_TRUSTED_PROXIES: web$", compose, re.MULTILINE)
    dockerfile = (root / "web" / "Dockerfile").read_text("utf-8")
    assert 'CMD ["node", "--import", "./preload/preload.mjs", "server.js"]' in dockerfile
    assert "/app/src/server ./preload" in dockerfile
