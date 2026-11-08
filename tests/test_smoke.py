"""Smoke tests for the project scaffold."""

from __future__ import annotations

from typer.testing import CliRunner

from webvigil import __version__
from webvigil.cli.app import app

runner = CliRunner()


def test_version_string_is_present() -> None:
    assert isinstance(__version__, str)
    assert __version__


def test_cli_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "webvigil" in result.stdout
