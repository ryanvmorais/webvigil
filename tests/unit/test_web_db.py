"""
Database layer: migrations, pragmas, and model/migration parity — RF-23, RF-24.

Each test builds a real SQLite database in ``tmp_path``, runs the Alembic
upgrade, and inspects the result — the table set, a downgrade back to base, the
WAL / foreign-key pragmas, and (the drift guard) that ``compare_metadata`` sees
no difference between the SQLModel models and the initial migration.
"""

from __future__ import annotations

import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.command import downgrade
from alembic.config import Config as AlembicConfig
from alembic.migration import MigrationContext
from fastapi.testclient import TestClient
from sqlalchemy import Connection, text
from sqlmodel import SQLModel

import webvigil.api.db  # noqa: F401 - registers tables on SQLModel.metadata
from webvigil.api.app import create_app
from webvigil.api.config import WebConfig
from webvigil.api.db import make_engine, run_alembic_upgrade

_MIGRATIONS = "src/webvigil/api/migrations"


def _config(tmp_path: Path) -> WebConfig:
    """
    Args:
        tmp_path (Path): The per-test temporary directory.

    Returns:
        WebConfig: A config whose database lives at ``tmp_path/webvigil.db``.
    """
    return WebConfig(database_path=tmp_path / "webvigil.db")


@contextmanager
def _connect(config: WebConfig) -> Iterator[Connection]:
    """
    Open a connection to the config's database, disposing the engine afterwards.

    Args:
        config (WebConfig): The config whose database to open.

    Yields:
        Connection: A connection from ``make_engine``; the engine is disposed afterwards, so no
            connection is left for the garbage collector to close.
    """
    engine = make_engine(config)
    try:
        with engine.connect() as conn:
            yield conn
    finally:
        engine.dispose()


def _tables(config: WebConfig) -> set[str]:
    """
    List the tables in the config's database.

    Args:
        config (WebConfig): The config whose database to read.

    Returns:
        set[str]: The names of the tables in it.
    """
    with _connect(config) as conn:
        rows = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).scalars()
        return set(rows)


def test_upgrade_creates_every_table(tmp_path: Path) -> None:
    """The Alembic upgrade creates the user / scan / finding / setting tables."""
    config = _config(tmp_path)
    run_alembic_upgrade(config)
    assert {"user", "scan", "finding", "setting", "alembic_version"} <= _tables(config)


def test_the_app_migrates_a_new_database_when_it_starts(tmp_path: Path) -> None:
    """With ``auto_migrate`` on (the default) the app's start-up creates the schema itself."""
    config = _config(tmp_path).model_copy(update={"allowed_hosts": ["testserver"]})
    with TestClient(create_app(config)) as client:
        assert client.get("/api/setup").json()["needs_setup"] is True
    assert {"user", "scan", "finding", "setting", "alembic_version"} <= _tables(config)


def test_downgrade_to_base_drops_the_schema(tmp_path: Path) -> None:
    """A downgrade to base leaves only Alembic's own version table."""
    config = _config(tmp_path)
    run_alembic_upgrade(config)
    alembic_cfg = AlembicConfig()
    alembic_cfg.set_main_option("script_location", _MIGRATIONS)
    alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{config.database_path}")
    downgrade(alembic_cfg, "base")
    assert _tables(config) == {"alembic_version"}


def test_wal_and_foreign_keys_are_on(tmp_path: Path) -> None:
    """A connection from ``make_engine`` has WAL journalling and foreign keys enabled."""
    config = _config(tmp_path)
    run_alembic_upgrade(config)
    with _connect(config) as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar() == "wal"
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1


def test_models_match_the_initial_migration(tmp_path: Path) -> None:
    """The SQLModel metadata has not drifted from the initial migration."""
    config = _config(tmp_path)
    run_alembic_upgrade(config)
    with _connect(config) as conn:
        context = MigrationContext.configure(
            conn, opts={"compare_type": True, "render_as_batch": True}
        )
        diff = compare_metadata(context, SQLModel.metadata)
    assert diff == [], f"models drifted from 0001_initial: {diff}"


# ---------------------------------------------------------------------------
# File permissions: the database holds the password hash and the session secret
# ---------------------------------------------------------------------------

_posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes; Windows uses ACLs")


@_posix_only
def test_a_new_database_is_readable_by_its_owner_only(tmp_path: Path) -> None:
    """The file is created ``0600`` before SQLite opens it, and so are its -wal and -shm."""
    config = WebConfig(database_path=tmp_path / "private" / "webvigil.db")
    run_alembic_upgrade(config)
    engine = make_engine(config)
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
        for path in (config.database_path, *config.database_path.parent.glob("webvigil.db-*")):
            assert stat.S_IMODE(path.stat().st_mode) == 0o600, path
    engine.dispose()
    assert stat.S_IMODE(config.database_path.parent.stat().st_mode) == 0o700


@_posix_only
def test_an_existing_database_is_tightened(tmp_path: Path) -> None:
    """A database an earlier version left world-readable, and its side files, become ``0600``."""
    config = _config(tmp_path)
    run_alembic_upgrade(config)
    wal = config.database_path.with_name(config.database_path.name + "-wal")
    wal.touch()
    for path in (config.database_path, wal):
        path.chmod(0o644)

    make_engine(config).dispose()

    for path in (config.database_path, wal):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path
