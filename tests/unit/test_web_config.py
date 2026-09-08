"""
WebConfig: defaults, TOML [web] table, env overrides — RF-31.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from webvigil.api.config import WebConfig
from webvigil.core.errors import ConfigError


def test_defaults() -> None:
    config = WebConfig()
    assert config.database_path == Path("webvigil.db")
    assert config.host == "127.0.0.1"
    assert config.port == 8000
    assert config.session_secret is None
    assert config.auto_migrate is True
    assert config.cors_origins == []


def test_reads_the_web_table(tmp_path: Path) -> None:
    path = tmp_path / "webvigil.toml"
    path.write_text(
        "[scan]\nmax_pages = 5\n\n[web]\nport = 9001\ncookie_secure = true\n"
        "cors_origins = ['http://localhost:3000']\n",
        "utf-8",
    )
    config = WebConfig.load(path)
    assert config.port == 9001
    assert config.cookie_secure is True
    assert config.cors_origins == ["http://localhost:3000"]


def test_no_web_table_gives_defaults(tmp_path: Path) -> None:
    path = tmp_path / "webvigil.toml"
    path.write_text("[scan]\nmax_pages = 5\n", "utf-8")
    assert WebConfig.load(path) == WebConfig()


def test_unknown_web_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "webvigil.toml"
    path.write_text("[web]\nnope = 1\n", "utf-8")
    with pytest.raises(ConfigError):
        WebConfig.load(path)


def test_env_overrides_win(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "webvigil.toml"
    path.write_text("[web]\nport = 8000\n", "utf-8")
    monkeypatch.setenv("WEBVIGIL_WEB_PORT", "7777")
    monkeypatch.setenv("WEBVIGIL_SESSION_SECRET", "s3cr3t")
    monkeypatch.setenv("WEBVIGIL_CORS_ORIGINS", "http://a.test, http://b.test")
    config = WebConfig.load(path)
    assert config.port == 7777
    assert config.session_secret == "s3cr3t"
    assert config.cors_origins == ["http://a.test", "http://b.test"]


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        WebConfig.load(tmp_path / "absent.toml")
