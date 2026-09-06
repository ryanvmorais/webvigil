"""Config model, TOML loading, and CLI-override precedence — RF-26."""

from __future__ import annotations

from pathlib import Path

import pytest

from webvigil.core import ConfigError, ScanConfig
from webvigil.core.findings import ScanMode


def test_defaults_match_the_example_file_shape() -> None:
    config = ScanConfig()
    assert config.scan.mode is ScanMode.PASSIVE
    assert config.scan.max_pages == 50
    assert config.http.concurrency == 8
    assert config.report.fail_on == "none"
    assert config.active is None


def test_load_reads_toml(tmp_path: Path) -> None:
    path = tmp_path / "webvigil.toml"
    path.write_text(
        "[scan]\nmode = 'active'\nmax_pages = 5\n\n[active]\nauthorized_by = 'Jane / #1'\n",
        "utf-8",
    )
    config = ScanConfig.load(path)
    assert config.scan.mode is ScanMode.ACTIVE
    assert config.scan.max_pages == 5
    assert config.active is not None and config.active.authorized_by == "Jane / #1"


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "webvigil.toml"
    path.write_text("[scan]\nnope = true\n", "utf-8")
    with pytest.raises(ConfigError):
        ScanConfig.load(path)


def test_web_section_is_tolerated_as_passthrough(tmp_path: Path) -> None:
    path = tmp_path / "webvigil.toml"
    path.write_text(
        "[scan]\nmax_pages = 7\n\n[web]\nport = 9000\ndatabase_path = 'x.db'\n", "utf-8"
    )
    config = ScanConfig.load(path)
    assert config.scan.max_pages == 7
    assert config.web == {"port": 9000, "database_path": "x.db"}


def test_a_misspelled_section_is_still_rejected(tmp_path: Path) -> None:
    path = tmp_path / "webvigil.toml"
    path.write_text("[scna]\nmax_pages = 7\n", "utf-8")
    with pytest.raises(ConfigError):
        ScanConfig.load(path)


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        ScanConfig.load(tmp_path / "absent.toml")


def test_cli_overrides_win_over_file_values() -> None:
    base = ScanConfig.model_validate({"scan": {"max_pages": 5}, "http": {"delay_ms": 100}})
    merged = base.with_overrides(scan={"max_pages": 99}, http={})
    assert merged.scan.max_pages == 99
    assert merged.http.delay_ms == 100  # untouched section stays


def test_overrides_ignore_empty_sections() -> None:
    base = ScanConfig()
    assert base.with_overrides(scan={}) == base
