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


def test_disclosure_probe_defaults_off_and_round_trips(tmp_path: Path) -> None:
    assert ScanConfig().disclosure.probe is False
    path = tmp_path / "webvigil.toml"
    path.write_text("[disclosure]\nprobe = true\n", "utf-8")
    assert ScanConfig.load(path).disclosure.probe is True


def test_unknown_disclosure_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "webvigil.toml"
    path.write_text("[disclosure]\nprobe = true\nnope = 1\n", "utf-8")
    with pytest.raises(ConfigError):
        ScanConfig.load(path)


def test_disclosure_override_wins_over_file() -> None:
    base = ScanConfig.model_validate({"disclosure": {"probe": False}})
    assert base.with_overrides(disclosure={"probe": True}).disclosure.probe is True


def test_injection_section_defaults_and_round_trips(tmp_path: Path) -> None:
    defaults = ScanConfig().injection
    assert defaults.request_budget == 500
    assert defaults.max_injection_points == 200
    assert defaults.time_based_sqli is True
    assert defaults.time_based_delay_s == 5
    assert defaults.stored_xss is False
    path = tmp_path / "webvigil.toml"
    path.write_text(
        "[injection]\nrequest_budget = 40\ntime_based_sqli = false\nstored_xss = true\n", "utf-8"
    )
    loaded = ScanConfig.load(path).injection
    assert loaded.request_budget == 40
    assert loaded.time_based_sqli is False
    assert loaded.stored_xss is True


def test_unknown_injection_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "webvigil.toml"
    path.write_text("[injection]\nrequest_budget = 40\nnope = 1\n", "utf-8")
    with pytest.raises(ConfigError):
        ScanConfig.load(path)


def test_injection_override_wins_over_file() -> None:
    base = ScanConfig.model_validate({"injection": {"time_based_sqli": True}})
    merged = base.with_overrides(injection={"time_based_sqli": False})
    assert merged.injection.time_based_sqli is False


def test_stored_xss_override_wins_over_file() -> None:
    base = ScanConfig.model_validate({"injection": {"stored_xss": False}})
    assert base.with_overrides(injection={"stored_xss": True}).injection.stored_xss is True


def test_auth_cookies_default_empty_and_round_trip(tmp_path: Path) -> None:
    assert ScanConfig().auth.cookies == []
    assert ScanConfig().auth.as_header == ""
    path = tmp_path / "webvigil.toml"
    path.write_text("[auth]\ncookies = ['session=abc', 'csrf=xyz']\n", "utf-8")
    loaded = ScanConfig.load(path).auth
    assert loaded.cookies == ["session=abc", "csrf=xyz"]
    assert loaded.as_header == "session=abc; csrf=xyz"


@pytest.mark.parametrize("bad", ["sessionabc", "=value", "   =v"])
def test_auth_cookie_without_a_valid_pair_is_rejected(tmp_path: Path, bad: str) -> None:
    path = tmp_path / "webvigil.toml"
    path.write_text(f"[auth]\ncookies = ['{bad}']\n", "utf-8")
    with pytest.raises(ConfigError):
        ScanConfig.load(path)


def test_unknown_auth_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "webvigil.toml"
    path.write_text("[auth]\ncookies = []\nheaders = ['X: 1']\n", "utf-8")
    with pytest.raises(ConfigError):
        ScanConfig.load(path)


def test_auth_cookies_override_replaces_the_file_list() -> None:
    base = ScanConfig.model_validate({"auth": {"cookies": ["a=1", "b=2"]}})
    merged = base.with_overrides(auth={"cookies": ["c=3"]})
    assert merged.auth.cookies == ["c=3"]


def test_submit_forms_defaults_on_and_round_trips(tmp_path: Path) -> None:
    assert ScanConfig().scan.submit_forms is True
    path = tmp_path / "webvigil.toml"
    path.write_text("[scan]\nsubmit_forms = false\n", "utf-8")
    assert ScanConfig.load(path).scan.submit_forms is False
