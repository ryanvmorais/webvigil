"""
Fixtures for the Web API tests: a fresh app + SQLite DB per test.

Every test gets its own ``web_config`` (a temp-dir copy of a database migrated once per run, and
a fixed session secret), so nothing leaks between tests. Argon2 runs at its lowest cost here:
these tests check which hash is verified, not how slowly. ``client`` wires a real app to
:class:`FakeOrchestrator` (instant, canned result); ``auth_client`` is that
client already through setup and login. :class:`BlockingOrchestrator` holds a
scan in RUNNING for the lifecycle tests.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from tests.support import make_finding, make_result
from webvigil.api import security
from webvigil.api.app import create_app
from webvigil.api.config import WebConfig
from webvigil.api.db import make_engine, run_alembic_upgrade
from webvigil.core import ScanConfig, ScanResult

ADMIN = {"username": "admin", "password": "password123"}


class FakeOrchestrator:
    """A stand-in orchestrator whose result the test controls."""

    result: ScanResult = make_result(make_finding())

    def __init__(self, _config: ScanConfig) -> None: ...

    async def run(self, raw_target: str) -> ScanResult:
        return type(self).result


class BlockingOrchestrator:
    """Never finishes on its own — used to hold a scan in RUNNING until cancelled."""

    def __init__(self, _config: ScanConfig) -> None: ...

    async def run(self, raw_target: str) -> ScanResult:
        import asyncio

        await asyncio.Event().wait()
        raise AssertionError("unreachable")  # pragma: no cover


@pytest.fixture(autouse=True)
def _reset_fake_result() -> Iterator[None]:
    """Restore ``FakeOrchestrator.result`` to its default before each test."""
    FakeOrchestrator.result = make_result(make_finding())
    yield


@pytest.fixture(scope="session")
def _migrated_database(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """
    Migrate a database once per run, for each test to start from a copy of.

    Returns:
        Path: A database migrated once per run, for each test to start from a copy of. A fresh
            migration costs about 80 ms and one already at head about 10 ms; the start-up
            migration of a brand-new file is tested in ``tests/unit/test_web_db.py``.
    """
    path = tmp_path_factory.mktemp("migrated") / "webvigil.db"
    run_alembic_upgrade(WebConfig(database_path=path))
    return path


@pytest.fixture
def web_config(tmp_path: Path, _migrated_database: Path) -> WebConfig:
    """
    Args:
        tmp_path (Path): pytest's per-test temp directory.
        _migrated_database (Path): The migrated database this test's copy starts from.

    Returns:
        WebConfig: A config over this test's own copy of the migrated database, with a fixed
            session secret, answering for ``testserver`` (the ``Host`` that ``TestClient`` sends).
    """
    database = tmp_path / "webvigil.db"
    shutil.copyfile(_migrated_database, database)
    return WebConfig(
        database_path=database,
        session_secret="test-session-secret-long-enough-for-hs256",
        session_ttl_hours=12,
        allowed_hosts=["testserver"],
    )


@pytest.fixture(autouse=True)
def _cheap_password_hashing(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """
    Hash with Argon2 at its lowest cost, so each setup and login is not a tenth of a second.

    These tests check which hash is verified, never how long it takes. The dummy hash is rebuilt
    with the cheap hasher and dropped again afterwards, so a later test gets the real one.
    """
    monkeypatch.setattr(
        security, "_hasher", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    )
    security.dummy_password_hash.cache_clear()
    yield
    security.dummy_password_hash.cache_clear()


@pytest.fixture
def web_engine(web_config: WebConfig) -> Iterator[Engine]:
    """
    Yields:
        Engine: A migrated engine over the per-test database, for tests that
            touch the DB directly; disposed afterwards, so no connection is left open.
    """
    run_alembic_upgrade(web_config)
    engine = make_engine(web_config)
    yield engine
    engine.dispose()


@pytest.fixture
def client(web_config: WebConfig) -> Iterator[TestClient]:
    """
    Yields:
        TestClient: A client for an app wired to :class:`FakeOrchestrator`, with
            its lifespan run.
    """
    app = create_app(web_config, orchestrator_factory=FakeOrchestrator)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_client(client: TestClient) -> TestClient:
    """
    Returns:
        TestClient: The same client after completing first-run setup and
            logging in as ``admin``.
    """
    assert client.post("/api/setup", json=ADMIN).status_code == 201
    assert client.post("/api/auth/login", json=ADMIN).status_code == 204
    return client
