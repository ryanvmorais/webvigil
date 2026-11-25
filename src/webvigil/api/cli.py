"""
The ``webvigil-web`` command: serve the API, run migrations, reset the password (RF-29).

The command docstrings double as Typer ``--help`` text, so they stay terse.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer
from sqlmodel import Session, select

from webvigil.api.config import WebConfig, insecure_bind_warning
from webvigil.api.db import User, make_engine, run_alembic_upgrade
from webvigil.api.schemas import PASSWORD_MAX_CHARS, PASSWORD_MIN_CHARS
from webvigil.api.security import hash_password, store_password_hash
from webvigil.core.errors import ConfigError
from webvigil.core.output import Sink, safe_text
from webvigil.core.secrets import Secret, SecretKind

app = typer.Typer(
    name="webvigil-web",
    help="Run the WebVigil Web API and manage its database.",
    no_args_is_help=True,
    add_completion=False,
)

# not ``readable``: the loader reads it and reports a failure with the operational exit code
_ConfigOpt = Annotated[
    Path | None, typer.Option("--config", help="Path to webvigil.toml.", readable=False)
]

# The engine's CLI uses the same code for an operational error; this package must not import it.
_EXIT_OPERATIONAL = 4


def _load(config: Path | None) -> WebConfig:
    """
    Args:
        config (Path | None): Path to a ``webvigil.toml``, or ``None`` for the default lookup.

    Returns:
        WebConfig: The validated configuration.

    Raises:
        typer.Exit: With the operational exit code and a one-line message when the configuration
            is invalid (a too-short ``session_secret``, a ``*`` in ``cors_origins``, a bad key).
    """
    try:
        return WebConfig.load(config)
    except ConfigError as exc:
        typer.echo(safe_text(f"error: {exc}", Sink.TERMINAL, one_line=True), err=True)
        raise typer.Exit(_EXIT_OPERATIONAL) from exc


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
    cfg = _load(config)
    bind = host or cfg.host
    warning = insecure_bind_warning(cfg, bind)
    if warning is not None:
        typer.echo(safe_text(f"warning: {warning}", Sink.TERMINAL, one_line=True), err=True)
    uvicorn.run(
        "webvigil.api.app:app",
        host=bind,
        port=port or cfg.port,
        reload=reload,
        # Off, or uvicorn would replace the connection's address with what a loopback peer wrote
        # in X-Forwarded-For. The API reads that header itself, under `web.trusted_proxies`.
        proxy_headers=False,
    )


@app.command()
def migrate(config: _ConfigOpt = None) -> None:
    """Run ``alembic upgrade head`` against the configured database."""
    cfg = _load(config)
    run_alembic_upgrade(cfg)
    typer.echo(safe_text(f"database migrated: {cfg.database_path}", Sink.TERMINAL, one_line=True))


@app.command(name="reset-password")
def reset_password(
    config: _ConfigOpt = None,
    username: Annotated[
        str | None, typer.Option(help="Which user (default: the only one).")
    ] = None,
) -> None:
    """Set a new password for the single user."""
    cfg = _load(config)
    run_alembic_upgrade(cfg)
    engine = make_engine(cfg)
    try:
        with Session(engine) as session:
            statement = select(User)
            if username is not None:
                statement = statement.where(User.username == username)
            user = session.exec(statement).first()
            if user is None:
                typer.echo(
                    "no user found — complete first-run setup in the browser first", err=True
                )
                raise typer.Exit(1)
            new_password = Secret(
                typer.prompt("New password", hide_input=True, confirmation_prompt=True),
                kind=SecretKind.PASSWORD,
            )
            # The same policy as setup and the password change, so a reset cannot set a password the
            # dashboard would have refused.
            if not PASSWORD_MIN_CHARS <= len(new_password) <= PASSWORD_MAX_CHARS:
                typer.echo(
                    f"error: the password must be {PASSWORD_MIN_CHARS} to {PASSWORD_MAX_CHARS} "
                    "characters long",
                    err=True,
                )
                raise typer.Exit(1)
            assert user.id is not None
            name = user.username
            if store_password_hash(session, user.id, hash_password(new_password)) is None:
                typer.echo(
                    "error: the password was changed by another request; run this again",
                    err=True,
                )
                raise typer.Exit(1)
            typer.echo(safe_text(f"password updated for {name}", Sink.TERMINAL, one_line=True))
    finally:
        engine.dispose()  # also on the refusals, which leave through typer.Exit


def main() -> None:
    """Console-script entry point for ``webvigil-web`` (see ``project.scripts``)."""
    app()
