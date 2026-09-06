"""The ``webvigil-web`` command: serve the API, run migrations, reset the password (RF-29)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer
from sqlmodel import Session, select

from webvigil.api.config import WebConfig
from webvigil.api.db import User, make_engine, run_alembic_upgrade, utcnow
from webvigil.api.security import hash_password

app = typer.Typer(
    name="webvigil-web",
    help="Run the WebVigil Web API and manage its database.",
    no_args_is_help=True,
    add_completion=False,
)

_ConfigOpt = Annotated[Path | None, typer.Option("--config", help="Path to webvigil.toml.")]


@app.command()
def serve(
    config: _ConfigOpt = None,
    host: Annotated[str | None, typer.Option(help="Bind host.")] = None,
    port: Annotated[int | None, typer.Option(help="Bind port.")] = None,
    reload: Annotated[bool, typer.Option(help="Auto-reload on code changes (dev only).")] = False,
) -> None:
    """Serve the API with uvicorn."""
    import uvicorn

    if config is not None:
        os.environ["WEBVIGIL_CONFIG"] = str(config)
    cfg = WebConfig.load(config)
    uvicorn.run(
        "webvigil.api.app:app",
        host=host or cfg.host,
        port=port or cfg.port,
        reload=reload,
    )


@app.command()
def migrate(config: _ConfigOpt = None) -> None:
    """Run ``alembic upgrade head`` against the configured database."""
    cfg = WebConfig.load(config)
    run_alembic_upgrade(cfg)
    typer.echo(f"database migrated: {cfg.database_path}")


@app.command(name="reset-password")
def reset_password(
    config: _ConfigOpt = None,
    username: Annotated[
        str | None, typer.Option(help="Which user (default: the only one).")
    ] = None,
) -> None:
    """Set a new password for the single user."""
    cfg = WebConfig.load(config)
    run_alembic_upgrade(cfg)
    engine = make_engine(cfg)
    with Session(engine) as session:
        statement = select(User)
        if username is not None:
            statement = statement.where(User.username == username)
        user = session.exec(statement).first()
        if user is None:
            typer.echo("no user found — complete first-run setup in the browser first", err=True)
            raise typer.Exit(1)
        new_password = typer.prompt("New password", hide_input=True, confirmation_prompt=True)
        user.password_hash = hash_password(new_password)
        user.updated_at = utcnow()
        session.add(user)
        session.commit()
        typer.echo(f"password updated for {user.username}")


def main() -> None:
    app()
