"""SQLModel tables, the engine factory, and the Alembic upgrade wrapper (RF-23, RF-24, RF-25).

This module is API-only. The engine never imports it.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, Column, Engine, String, event
from sqlmodel import Field, Session, SQLModel, create_engine

from webvigil.api.config import WebConfig

_MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def utcnow() -> datetime:
    return datetime.now(UTC)


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


TERMINAL_STATUSES: frozenset[ScanStatus] = frozenset(
    {
        ScanStatus.COMPLETED,
        ScanStatus.FAILED,
        ScanStatus.CANCELLED,
        ScanStatus.INTERRUPTED,
    }
)


class User(SQLModel, table=True):
    __tablename__ = "user"

    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    password_hash: str
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class Scan(SQLModel, table=True):
    __tablename__ = "scan"

    id: int | None = Field(default=None, primary_key=True)
    target: str
    mode: str
    scope: str
    options: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    # Plain string column (stores the StrEnum value, e.g. "queued") rather than a DB enum.
    status: ScanStatus = Field(
        default=ScanStatus.QUEUED,
        sa_column=Column("status", String, index=True, nullable=False),
    )
    authorized_by: str | None = None
    tool_version: str | None = None
    error: str | None = None
    created_at: datetime = Field(default_factory=utcnow, index=True)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    pages_scanned: int = 0
    counts: dict[str, int] = Field(default_factory=dict, sa_column=Column(JSON))
    check_errors: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    warnings: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    # Detected-technology inventory (spec 004, RF-17). Additive; NULL for pre-004 scans.
    technologies: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))


class Finding(SQLModel, table=True):
    __tablename__ = "finding"

    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True, ondelete="CASCADE")
    check_id: str
    severity: int
    confidence: int
    title: str
    description: str
    location: dict[str, Any] = Field(sa_column=Column(JSON))
    remediation: str
    evidence: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    cwe: list[int] = Field(default_factory=list, sa_column=Column(JSON))
    references: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    fingerprint: str


class Setting(SQLModel, table=True):
    __tablename__ = "setting"

    key: str = Field(primary_key=True)
    value: str


def make_engine(config: WebConfig) -> Engine:
    """Create the SQLite engine, enabling WAL and foreign-key enforcement per connection."""
    path = config.database_path
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


@contextmanager
def session_scope(engine: Engine) -> Iterator[Session]:
    """A session that commits on clean exit and rolls back on error."""
    with Session(engine) as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise


def run_alembic_upgrade(config: WebConfig) -> None:
    """Run ``alembic upgrade head`` against the configured database."""
    from alembic import command
    from alembic.config import Config as AlembicConfig

    alembic_cfg = AlembicConfig()
    alembic_cfg.set_main_option("script_location", str(_MIGRATIONS_DIR))
    alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{config.database_path}")
    command.upgrade(alembic_cfg, "head")
