"""
The webvigil-web command: migrate, reset-password, serve — RF-29.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlmodel import Session, select
from typer.testing import CliRunner

from webvigil.api import cli
from webvigil.api.config import WebConfig
from webvigil.api.db import User, make_engine, run_alembic_upgrade
from webvigil.api.security import hash_password, verify_password

runner = CliRunner()


@pytest.fixture(autouse=True)
def _config_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    toml = tmp_path / "webvigil.toml"
    toml.write_text(f'[web]\ndatabase_path = "{(tmp_path / "wv.db").as_posix()}"\n', "utf-8")
    monkeypatch.setenv("WEBVIGIL_CONFIG", str(toml))
    return tmp_path


def test_migrate_creates_the_schema(_config_env: Path) -> None:
    result = runner.invoke(cli.app, ["migrate"])
    assert result.exit_code == 0
    engine = make_engine(WebConfig.load())
    with engine.connect() as conn:
        from sqlalchemy import text

        tables = set(
            conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).scalars()
        )
    assert {"user", "scan", "finding"} <= tables


def test_reset_password_updates_the_hash(_config_env: Path) -> None:
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


def test_reset_password_without_a_user_errors(_config_env: Path) -> None:
    result = runner.invoke(cli.app, ["reset-password"], input="x\nx\n")
    assert result.exit_code == 1
    assert "no user found" in result.output


def test_serve_invokes_uvicorn(_config_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
