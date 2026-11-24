"""
The webvigil-web command: migrate, reset-password, serve — RF-29.

The autouse ``_config_env`` fixture writes a ``webvigil.toml`` pointing at a
temp-dir database and sets ``WEBVIGIL_CONFIG``, so each ``CliRunner`` invocation
of the real Typer app operates on a fresh DB. ``serve`` is tested with
``uvicorn.run`` monkeypatched so nothing actually binds a port.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlmodel import Session, select
from typer.testing import CliRunner

from webvigil.api import cli
from webvigil.api.config import WebConfig
from webvigil.api.db import User, make_engine, run_alembic_upgrade
from webvigil.api.security import hash_password, verify_password

runner = CliRunner()


@pytest.fixture(autouse=True)
def _config_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """
    Write a temp ``webvigil.toml`` and point ``WEBVIGIL_CONFIG`` at it.

    Args:
        tmp_path (Path): pytest's per-test temp directory.
        monkeypatch (pytest.MonkeyPatch): used to set the config env var.

    Returns:
        Path: ``tmp_path``, for tests that need the directory.
    """
    toml = tmp_path / "webvigil.toml"
    toml.write_text(f'[web]\ndatabase_path = "{(tmp_path / "wv.db").as_posix()}"\n', "utf-8")
    monkeypatch.setenv("WEBVIGIL_CONFIG", str(toml))
    return tmp_path


def test_migrate_creates_the_schema(_config_env: Path) -> None:
    """``webvigil-web migrate`` creates the user / scan / finding tables."""
    result = runner.invoke(cli.app, ["migrate"])
    assert result.exit_code == 0
    engine = make_engine(WebConfig.load())
    with engine.connect() as conn:
        from sqlalchemy import text

        tables = set(
            conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).scalars()
        )
    engine.dispose()
    assert {"user", "scan", "finding"} <= tables


def test_reset_password_updates_the_hash(_config_env: Path) -> None:
    """``reset-password`` replaces the stored hash: the new password verifies, the old does not."""
    config = WebConfig.load()
    run_alembic_upgrade(config)
    engine = make_engine(config)
    with Session(engine) as session:
        session.add(User(username="admin", password_hash=hash_password("old-password")))
        session.commit()

    result = runner.invoke(
        cli.app, ["reset-password", "--username", "admin"], input="new-password\nnew-password\n"
    )
    assert result.exit_code == 0

    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == "admin")).one()
        assert verify_password("new-password", user.password_hash)
        assert not verify_password("old-password", user.password_hash)
    engine.dispose()


def test_reset_password_writes_through_the_shared_stamp(
    _config_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reset ends sessions the way the API's change does, with no condition on the old hash."""
    config = WebConfig.load()
    run_alembic_upgrade(config)
    engine = make_engine(config)
    with Session(engine) as session:
        session.add(User(username="admin", password_hash=hash_password("old-password")))
        session.commit()
    calls: list[str | None] = []
    real_store = cli.store_password_hash

    def spy(
        session: Session, user_id: int, new_hash: str, *, expected_hash: str | None = None
    ) -> datetime | None:
        calls.append(expected_hash)
        return real_store(session, user_id, new_hash, expected_hash=expected_hash)

    monkeypatch.setattr(cli, "store_password_hash", spy)
    result = runner.invoke(cli.app, ["reset-password"], input="new-password\nnew-password\n")
    assert result.exit_code == 0
    assert "password updated for admin" in result.output
    assert calls == [None]
    engine.dispose()


def test_reset_password_says_so_when_another_change_replaced_it(
    _config_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reset overtaken before its stamp did not set the current password: it must not say so."""
    config = WebConfig.load()
    run_alembic_upgrade(config)
    engine = make_engine(config)
    with Session(engine) as session:
        session.add(User(username="admin", password_hash=hash_password("old-password")))
        session.commit()
    calls: list[int] = []

    def overtaken(_session: Session, user_id: int, _new_hash: str) -> None:
        calls.append(user_id)

    monkeypatch.setattr(cli, "store_password_hash", overtaken)
    result = runner.invoke(cli.app, ["reset-password"], input="new-password\nnew-password\n")

    assert calls == [1]
    assert result.exit_code == 1
    assert "error: the password was changed by another request; run this again" in result.output
    assert "password updated" not in result.output
    engine.dispose()


def test_reset_password_refuses_a_password_the_api_would_refuse(_config_env: Path) -> None:
    """A reset follows the API's policy: a seven-character password is refused, the hash kept."""
    config = WebConfig.load()
    run_alembic_upgrade(config)
    engine = make_engine(config)
    with Session(engine) as session:
        session.add(User(username="admin", password_hash=hash_password("old-password")))
        session.commit()

    result = runner.invoke(cli.app, ["reset-password"], input="short12\nshort12\n")
    assert result.exit_code == 1
    assert "8 to 256 characters" in result.output

    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == "admin")).one()
        assert verify_password("old-password", user.password_hash)
    engine.dispose()


def test_reset_password_without_a_user_errors(_config_env: Path) -> None:
    """``reset-password`` with no matching user exits non-zero with a clear message."""
    result = runner.invoke(cli.app, ["reset-password"], input="x\nx\n")
    assert result.exit_code == 1
    assert "no user found" in result.output


@pytest.mark.parametrize(
    ("with_user", "password", "exit_code"),
    [
        (True, "new-password", 0),  # the password is changed
        (False, "new-password", 1),  # no user to change
        (True, "short12", 1),  # a password the API would refuse
    ],
)
def test_reset_password_closes_its_database_on_every_way_out(
    monkeypatch: pytest.MonkeyPatch, with_user: bool, password: str, exit_code: int
) -> None:
    """Success or either refusal, the command disposes the engine it opened."""
    config = WebConfig.load()
    run_alembic_upgrade(config)
    if with_user:
        seed = make_engine(config)
        with Session(seed) as session:
            session.add(User(username="admin", password_hash=hash_password("old-password")))
            session.commit()
        seed.dispose()

    opened: list[Engine] = []
    disposed: list[Engine] = []

    def tracked(cfg: WebConfig) -> Engine:
        """
        Args:
            cfg (WebConfig): The config the command loaded.

        Returns:
            Engine: The real engine, with ``dispose`` recorded.
        """
        engine = make_engine(cfg)
        opened.append(engine)
        real_dispose = engine.dispose

        def dispose(close: bool = True) -> None:
            disposed.append(engine)
            real_dispose(close)

        monkeypatch.setattr(engine, "dispose", dispose)
        return engine

    monkeypatch.setattr(cli, "make_engine", tracked)
    result = runner.invoke(cli.app, ["reset-password"], input=f"{password}\n{password}\n")
    assert result.exit_code == exit_code, result.output
    assert len(opened) == 1
    assert disposed == opened


def test_serve_invokes_uvicorn(_config_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``serve`` calls ``uvicorn.run`` with the app path and the resolved host/port."""
    calls: dict[str, object] = {}

    def _fake_run(target: str, **kwargs: object) -> None:
        calls["target"] = target
        calls.update(kwargs)

    import uvicorn

    monkeypatch.setattr(uvicorn, "run", _fake_run)
    result = runner.invoke(cli.app, ["serve", "--port", "9123"])
    assert result.exit_code == 0
    assert calls["target"] == "webvigil.api.app:app"
    assert calls["port"] == 9123
    assert calls["host"] == "127.0.0.1"
    # uvicorn's own handling would let a loopback peer choose the address the API sees.
    assert calls["proxy_headers"] is False


def _stub_uvicorn(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """
    Args:
        monkeypatch (pytest.MonkeyPatch): Used to replace ``uvicorn.run``.

    Returns:
        dict[str, object]: Filled with the host and port ``serve`` passes to uvicorn.
    """
    calls: dict[str, object] = {}

    def _fake_run(target: str, **kwargs: object) -> None:
        calls.update(kwargs)

    import uvicorn

    monkeypatch.setattr(uvicorn, "run", _fake_run)
    return calls


def test_serve_warns_when_it_listens_beyond_this_machine_with_an_insecure_cookie(
    _config_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--host 0.0.0.0`` with ``cookie_secure`` off prints a warning and still starts."""
    calls = _stub_uvicorn(monkeypatch)
    result = runner.invoke(cli.app, ["serve", "--host", "0.0.0.0"])
    assert result.exit_code == 0 and calls["host"] == "0.0.0.0"
    assert "warning: listening on 0.0.0.0" in result.stderr and "cookie_secure" in result.stderr

    quiet = runner.invoke(cli.app, ["serve"])  # the default bind is 127.0.0.1
    assert quiet.exit_code == 0 and "warning" not in quiet.stderr


def test_a_short_session_secret_stops_serve_with_one_clear_line(
    _config_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An invalid config is an operational error (exit 4) with a message, not a traceback."""
    calls = _stub_uvicorn(monkeypatch)
    monkeypatch.setenv("WEBVIGIL_SESSION_SECRET", "change-me")
    result = runner.invoke(cli.app, ["serve"])
    assert result.exit_code == 4 and not calls
    assert "error:" in result.stderr and "at least 32 characters" in result.stderr
    assert "Traceback" not in result.output
