"""WebVigil CLI entry point.

This is a scaffold. The `scan`, `report`, and `list-checks` commands are designed and
implemented as part of the `001-foundation` spec.
"""

from __future__ import annotations

import typer

from webvigil import __version__

app = typer.Typer(
    name="webvigil",
    help="A web application vulnerability scanner for developers. Safe by default.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def _root() -> None:
    """A web application vulnerability scanner for developers. Safe by default."""


@app.command()
def version() -> None:
    """Print the WebVigil version."""
    typer.echo(f"webvigil {__version__}")


def main() -> None:
    """Console-script entry point (see `project.scripts` in pyproject.toml)."""
    app()


if __name__ == "__main__":
    main()
