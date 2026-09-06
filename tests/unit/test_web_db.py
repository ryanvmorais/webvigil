"""Database layer: migrations, pragmas, and model/migration parity — RF-23, RF-24."""

from __future__ import annotations

from pathlib import Path

from alembic.autogenerate import compare_metadata
from alembic.command import downgrade
from alembic.config import Config as AlembicConfig
from alembic.migration import MigrationContext
from sqlalchemy import text
from sqlmodel import SQLModel

import webvigil.api.db  # noqa: F401 - registers tables on SQLModel.metadata
from webvigil.api.config import WebConfig
from webvigil.api.db import make_engine, run_alembic_upgrade

_MIGRATIONS = "src/webvigil/api/migrations"


def _config(tmp_path: Path) -> WebConfig:
    return WebConfig(database_path=tmp_path / "webvigil.db")


def test_upgrade_creates_every_table(tmp_path: Path) -> None:
    config = _config(tmp_path)
    run_alembic_upgrade(config)
    with make_engine(config).connect() as conn:
        rows = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).scalars()
        tables = set(rows)
    assert {"user", "scan", "finding", "setting", "alembic_version"} <= tables


def test_downgrade_to_base_drops_the_schema(tmp_path: Path) -> None:
    config = _config(tmp_path)
    run_alembic_upgrade(config)
    alembic_cfg = AlembicConfig()
    alembic_cfg.set_main_option("script_location", _MIGRATIONS)
    alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{config.database_path}")
    downgrade(alembic_cfg, "base")
    with make_engine(config).connect() as conn:
        rows = set(
            conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).scalars()
        )
    assert rows == {"alembic_version"}


def test_wal_and_foreign_keys_are_on(tmp_path: Path) -> None:
    config = _config(tmp_path)
    run_alembic_upgrade(config)
    with make_engine(config).connect() as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar() == "wal"
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1


def test_models_match_the_initial_migration(tmp_path: Path) -> None:
    config = _config(tmp_path)
    run_alembic_upgrade(config)
    with make_engine(config).connect() as conn:
        context = MigrationContext.configure(
            conn, opts={"compare_type": True, "render_as_batch": True}
        )
        diff = compare_metadata(context, SQLModel.metadata)
    assert diff == [], f"models drifted from 0001_initial: {diff}"
