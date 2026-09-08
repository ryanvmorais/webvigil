"""
SQLModel tables, the engine factory, and the Alembic upgrade wrapper (RF-23, RF-24, RF-25).

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
    """
    Returns:
        datetime: The current time, timezone-aware in UTC.
    """
    return datetime.now(UTC)


class ScanStatus(StrEnum):
    """
    Lifecycle state of a stored scan.

    Attributes:
        QUEUED (str): Waiting for the runner's execution slot.
        RUNNING (str): Currently executing.
        COMPLETED (str): Finished; findings are stored.
        FAILED (str): Ended with a controlled engine error or a crash.
        CANCELLED (str): Cancelled by the user.
        INTERRUPTED (str): Left ``RUNNING`` by a process that died; recovered on
            the next startup.
    """

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
    """
    The single account (first-run setup creates it).

    Attributes:
        id (int | None): Primary key.
        username (str): Unique, indexed login name.
        password_hash (str): Argon2 hash.
        created_at (datetime): When the account was created (UTC).
        updated_at (datetime): When it was last changed, e.g. a password reset.
    """

    __tablename__ = "user"

    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    password_hash: str
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class Scan(SQLModel, table=True):
    """
    One scan request and its result metadata.

    Attributes:
        id (int | None): Primary key.
        target (str): The requested target URL.
        mode (str): ``"passive"`` or ``"active"``.
        scope (str): ``"host"`` or ``"subdomains"``.
        options (dict[str, Any]): The extra overrides from the request
            (``max_pages``, ``delay_ms``, ``follow_robots``, ``fail_on``,
            ``disabled_checks``).
        status (ScanStatus): Lifecycle state; stored as its string value in a
            plain, indexed ``String`` column.
        authorized_by (str | None): Active-Mode attestation.
        tool_version (str | None): WebVigil version that ran the scan.
        error (str | None): Failure message, when ``status`` is ``FAILED`` /
            ``INTERRUPTED``.
        created_at (datetime): When the request was queued (indexed).
        started_at (datetime | None): When execution began.
        finished_at (datetime | None): When execution ended.
        pages_scanned (int): Pages the crawler fetched.
        counts (dict[str, int]): Finding count per severity name.
        check_errors (list[dict[str, Any]]): Serialised
            :class:`~webvigil.core.result.CheckError` entries.
        warnings (list[str]): Scan warnings.
        technologies (list[dict[str, Any]]): Detected-technology inventory
            (spec 004, RF-17); empty for pre-004 scans.
    """

    __tablename__ = "scan"

    id: int | None = Field(default=None, primary_key=True)
    target: str
    mode: str
    scope: str
    options: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
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
    technologies: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))


class Finding(SQLModel, table=True):
    """
    One stored finding, belonging to a :class:`Scan`.

    Attributes:
        id (int | None): Primary key.
        scan_id (int): Owning scan; ``ON DELETE CASCADE``.
        check_id (str): The check that produced it.
        severity (int): The :class:`~webvigil.core.findings.Severity` integer
            value.
        confidence (int): The :class:`~webvigil.core.findings.Confidence`
            integer value.
        title (str): One-line summary.
        description (str): Full explanation.
        location (dict[str, Any]): Serialised
            :class:`~webvigil.core.findings.Location`.
        remediation (str): How to fix it.
        evidence (list[dict[str, Any]]): Serialised evidence items.
        cwe (list[int]): CWE ids.
        references (list[str]): Further-reading URLs.
        fingerprint (str): Stable dedup identity.
    """

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
    """
    A single key/value row for process-wide settings (currently just the session secret).

    Attributes:
        key (str): Setting name (primary key).
        value (str): Its string value.
    """

    __tablename__ = "setting"

    key: str = Field(primary_key=True)
    value: str


def make_engine(config: WebConfig) -> Engine:
    """
    Create the SQLite engine, enabling WAL and foreign-key enforcement per connection.

    Args:
        config (WebConfig): Supplies ``database_path``; the parent directory is
            created if needed.

    Returns:
        Engine: The configured SQLAlchemy engine.
    """
    path = config.database_path
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_connection: Any, _record: Any) -> None:
        """Enable WAL journalling and foreign-key enforcement on every new connection."""
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


@contextmanager
def session_scope(engine: Engine) -> Iterator[Session]:
    """
    A transactional session context.

    Args:
        engine (Engine): The DB engine.

    Yields:
        Session: A session that commits on a clean exit and rolls back on any
            exception.
    """
    with Session(engine) as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise


def run_alembic_upgrade(config: WebConfig) -> None:
    """
    Run ``alembic upgrade head`` against the configured database.

    Args:
        config (WebConfig): Supplies ``database_path``.
    """
    from alembic import command
    from alembic.config import Config as AlembicConfig

    alembic_cfg = AlembicConfig()
    alembic_cfg.set_main_option("script_location", str(_MIGRATIONS_DIR))
    alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{config.database_path}")
    command.upgrade(alembic_cfg, "head")
