"""
Fixtures for the Web API tests: a fresh app + SQLite DB per test.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from tests.support import make_finding, make_result
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


@pytest.fixture
def web_config(tmp_path: Path) -> WebConfig:
    """
    Args:
        tmp_path (Path): pytest's per-test temp directory.

    Returns:
        WebConfig: A config with a fresh SQLite path and a fixed session secret.
    """
    return WebConfig(
        database_path=tmp_path / "webvigil.db",
        session_secret="test-session-secret-long-enough-for-hs256",
        session_ttl_hours=12,
    )


@pytest.fixture
def web_engine(web_config: WebConfig) -> Engine:
    """
    Returns:
        Engine: A migrated engine over the per-test database, for tests that
            touch the DB directly.
    """
    run_alembic_upgrade(web_config)
    return make_engine(web_config)


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
