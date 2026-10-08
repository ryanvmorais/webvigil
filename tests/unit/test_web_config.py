"""
WebConfig: defaults, TOML [web] table, env overrides — RF-31.

Same shape as the engine's config tests: assert the defaults, load a
``webvigil.toml`` from ``tmp_path`` and check the ``[web]`` table maps in,
confirm ``WEBVIGIL_*`` environment variables win over the file, and that an
unknown key or a missing file raises :class:`ConfigError`.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from webvigil.api.config import WebConfig, insecure_bind_warning
from webvigil.core.errors import ConfigError

# A pinned secret must be at least 32 characters (HS256 key length).
_SECRET = "s" * 32


def test_defaults() -> None:
    """A bare :class:`WebConfig` has the documented host/port/secret/migrate defaults."""
    config = WebConfig()
    assert config.database_path == Path("webvigil.db")
    assert config.host == "127.0.0.1"
    assert config.port == 8000
    assert config.session_secret is None
    assert config.auto_migrate is True
    assert config.cors_origins == []


def test_reads_the_web_table(tmp_path: Path) -> None:
    """The ``[web]`` table's keys map onto the typed config, including the CORS list."""
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
    """A config file with no ``[web]`` table loads to the plain defaults."""
    path = tmp_path / "webvigil.toml"
    path.write_text("[scan]\nmax_pages = 5\n", "utf-8")
    assert WebConfig.load(path) == WebConfig()


def test_unknown_web_key_is_rejected(tmp_path: Path) -> None:
    """An unknown key under ``[web]`` is a :class:`ConfigError`."""
    path = tmp_path / "webvigil.toml"
    path.write_text("[web]\nnope = 1\n", "utf-8")
    with pytest.raises(ConfigError):
        WebConfig.load(path)


def test_env_overrides_win(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``WEBVIGIL_*`` environment variables override the file, CORS list included."""
    path = tmp_path / "webvigil.toml"
    path.write_text("[web]\nport = 8000\n", "utf-8")
    monkeypatch.setenv("WEBVIGIL_WEB_PORT", "7777")
    monkeypatch.setenv("WEBVIGIL_SESSION_SECRET", _SECRET)
    monkeypatch.setenv("WEBVIGIL_CORS_ORIGINS", "http://a.test, http://b.test")
    config = WebConfig.load(path)
    assert config.port == 7777
    assert config.session_secret == _SECRET
    assert config.cors_origins == ["http://a.test", "http://b.test"]


def test_missing_file_raises(tmp_path: Path) -> None:
    """Loading a file that does not exist is a :class:`ConfigError`."""
    with pytest.raises(ConfigError):
        WebConfig.load(tmp_path / "absent.toml")


# ---------------------------------------------------------------------------
# Hardening for 1.0.1: secret length, wildcard CORS, insecure bind (issue #139)
# ---------------------------------------------------------------------------


def test_a_short_pinned_session_secret_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A pinned secret under 32 characters fails validation, and ``load`` says what to do."""
    with pytest.raises(ValidationError, match="at least 32 characters"):
        WebConfig(session_secret="change-me")
    monkeypatch.setenv("WEBVIGIL_SESSION_SECRET", "change-me")
    with pytest.raises(ConfigError, match="token_urlsafe"):
        WebConfig.load()


def test_a_secret_of_32_characters_is_accepted_and_an_empty_one_means_unset() -> None:
    """The limit is inclusive; an empty string (what an empty env var gives) still means unset."""
    assert WebConfig(session_secret="k" * 32).session_secret == "k" * 32
    assert WebConfig(session_secret="").session_secret == ""
    with pytest.raises(ValidationError):
        WebConfig(session_secret="k" * 31)


def test_a_wildcard_cors_origin_is_refused_because_the_api_sends_credentials() -> None:
    """A star is rejected, alone or in a list; explicit origins are fine."""
    for origins in (["*"], ["http://a.test", "*"]):
        with pytest.raises(ValidationError, match="not allowed"):
            WebConfig(cors_origins=origins)
    assert WebConfig(cors_origins=["http://a.test"]).cors_origins == ["http://a.test"]


def test_insecure_bind_warning_only_for_a_reachable_address_without_a_secure_cookie() -> None:
    """Loopback never warns; any other bind warns unless the cookie is ``Secure``."""
    plain = WebConfig()
    secure = WebConfig(cookie_secure=True)
    for host in ("127.0.0.1", "127.0.0.2", "::1", "localhost", "LOCALHOST"):
        assert insecure_bind_warning(plain, host) is None, host
    for host in ("0.0.0.0", "192.168.1.5", "::", "example.test"):
        message = insecure_bind_warning(plain, host)
        assert message is not None and host in message and "cookie_secure" in message, host
        assert insecure_bind_warning(secure, host) is None, host
