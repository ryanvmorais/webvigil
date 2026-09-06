"""Alembic environment for the WebVigil Web API.

The database URL is supplied by ``webvigil.api.db.run_alembic_upgrade`` (programmatic) or,
for a bare ``alembic`` shell command, derived from ``WebConfig`` / ``WEBVIGIL_CONFIG``.
"""

from __future__ import annotations

import os

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlmodel import SQLModel

import webvigil.api.db  # noqa: F401 - registers the tables on SQLModel.metadata
from webvigil.api.config import WebConfig

config = context.config
target_metadata = SQLModel.metadata

_PLACEHOLDER_URL = "driver://user:pass@localhost/dbname"


def _database_url() -> str:
    url = config.get_main_option("sqlalchemy.url")
    if url and url != _PLACEHOLDER_URL:
        return url
    web_config = WebConfig.load(os.environ.get("WEBVIGIL_CONFIG"))
    return f"sqlite:///{web_config.database_path}"


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
