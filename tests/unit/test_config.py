"""
Config model, TOML loading, and CLI-override precedence — RF-26.

Each section follows the same shape: assert the defaults, write a ``webvigil.toml``
under ``tmp_path`` and check it round-trips through :meth:`ScanConfig.load`, and
check that a ``with_overrides`` value beats the file. Unknown keys and misspelled
sections must raise :class:`ConfigError` rather than being silently dropped.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from webvigil.core import ConfigError, ScanConfig
from webvigil.core.findings import ScanMode

# ---------------------------------------------------------------------------
# Defaults, loading, and override precedence
# ---------------------------------------------------------------------------


def test_defaults_match_the_example_file_shape() -> None:
    """A bare :class:`ScanConfig` has the documented defaults (Passive, 50 pages, ...)."""
    config = ScanConfig()
    assert config.scan.mode is ScanMode.PASSIVE
    assert config.scan.max_pages == 50
    assert config.http.concurrency == 8
    assert config.report.fail_on == "none"
    assert config.active is None


def test_load_reads_toml(tmp_path: Path) -> None:
    """``load`` reads a TOML file into the typed model, including the ``[active]`` block."""
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
    """An unknown key inside a known section is a :class:`ConfigError`."""
    path = tmp_path / "webvigil.toml"
    path.write_text("[scan]\nnope = true\n", "utf-8")
    with pytest.raises(ConfigError):
        ScanConfig.load(path)


def test_web_section_is_tolerated_as_passthrough(tmp_path: Path) -> None:
    """The ``[web]`` table is kept verbatim for the API to read, not validated here."""
    path = tmp_path / "webvigil.toml"
    path.write_text(
        "[scan]\nmax_pages = 7\n\n[web]\nport = 9000\ndatabase_path = 'x.db'\n", "utf-8"
    )
    config = ScanConfig.load(path)
    assert config.scan.max_pages == 7
    assert config.web == {"port": 9000, "database_path": "x.db"}


def test_a_misspelled_section_is_still_rejected(tmp_path: Path) -> None:
    """A misspelled section name (``[scna]``) is rejected, not ignored."""
    path = tmp_path / "webvigil.toml"
    path.write_text("[scna]\nmax_pages = 7\n", "utf-8")
    with pytest.raises(ConfigError):
        ScanConfig.load(path)


def test_missing_file_raises(tmp_path: Path) -> None:
    """Pointing ``load`` at a file that does not exist is a :class:`ConfigError`."""
    with pytest.raises(ConfigError):
        ScanConfig.load(tmp_path / "absent.toml")


def test_cli_overrides_win_over_file_values() -> None:
    """A CLI override replaces its key; sections the override does not touch are untouched."""
    base = ScanConfig.model_validate({"scan": {"max_pages": 5}, "http": {"delay_ms": 100}})
    merged = base.with_overrides(scan={"max_pages": 99}, http={})
    assert merged.scan.max_pages == 99
    assert merged.http.delay_ms == 100  # untouched section stays


def test_overrides_ignore_empty_sections() -> None:
    """An empty override dict is a no-op, not a reset to defaults."""
    base = ScanConfig()
    assert base.with_overrides(scan={}) == base


# ---------------------------------------------------------------------------
# The [disclosure] section (spec 005)
# ---------------------------------------------------------------------------


def test_disclosure_probe_defaults_off_and_round_trips(tmp_path: Path) -> None:
    """``[disclosure] probe`` defaults off and round-trips through a TOML file."""
    assert ScanConfig().disclosure.probe is False
    path = tmp_path / "webvigil.toml"
    path.write_text("[disclosure]\nprobe = true\n", "utf-8")
    assert ScanConfig.load(path).disclosure.probe is True


def test_unknown_disclosure_key_is_rejected(tmp_path: Path) -> None:
    """An unknown key under ``[disclosure]`` is a :class:`ConfigError`."""
    path = tmp_path / "webvigil.toml"
    path.write_text("[disclosure]\nprobe = true\nnope = 1\n", "utf-8")
    with pytest.raises(ConfigError):
        ScanConfig.load(path)


def test_disclosure_override_wins_over_file() -> None:
    """A ``disclosure`` override beats the file value."""
    base = ScanConfig.model_validate({"disclosure": {"probe": False}})
    assert base.with_overrides(disclosure={"probe": True}).disclosure.probe is True


# ---------------------------------------------------------------------------
# The [injection] section (specs 006 / 008)
# ---------------------------------------------------------------------------


def test_injection_section_defaults_and_round_trips(tmp_path: Path) -> None:
    """``[injection]`` has the documented budget/point/time-based defaults and round-trips."""
    defaults = ScanConfig().injection
    assert defaults.request_budget == 650
    assert defaults.max_injection_points == 200
    assert defaults.time_based_sqli is True
    assert defaults.time_based_cmdi is True
    assert defaults.time_based_delay_s == 5
    assert defaults.stored_xss is False
    assert defaults.xxe is False
    assert defaults.file_upload is False
    assert defaults.upload_budget == 80
    assert defaults.envelope_url_sample == 15
    path = tmp_path / "webvigil.toml"
    path.write_text(
        "[injection]\nrequest_budget = 40\ntime_based_sqli = false\n"
        "time_based_cmdi = false\nstored_xss = true\nxxe = true\nfile_upload = true\n",
        "utf-8",
    )
    loaded = ScanConfig.load(path).injection
    assert loaded.request_budget == 40
    assert loaded.time_based_sqli is False
    assert loaded.time_based_cmdi is False
    assert loaded.stored_xss is True
    assert loaded.xxe is True
    assert loaded.file_upload is True


def test_unknown_injection_key_is_rejected(tmp_path: Path) -> None:
    """An unknown key under ``[injection]`` is a :class:`ConfigError`."""
    path = tmp_path / "webvigil.toml"
    path.write_text("[injection]\nrequest_budget = 40\nnope = 1\n", "utf-8")
    with pytest.raises(ConfigError):
        ScanConfig.load(path)


def test_injection_override_wins_over_file() -> None:
    """An ``injection`` override beats the file value."""
    base = ScanConfig.model_validate({"injection": {"time_based_sqli": True}})
    merged = base.with_overrides(injection={"time_based_sqli": False})
    assert merged.injection.time_based_sqli is False


def test_stored_xss_override_wins_over_file() -> None:
    """The ``stored_xss`` opt-in can be turned on by an override over an off file value."""
    base = ScanConfig.model_validate({"injection": {"stored_xss": False}})
    assert base.with_overrides(injection={"stored_xss": True}).injection.stored_xss is True


def test_time_based_cmdi_override_wins_over_file() -> None:
    """The ``--no-time-based-cmdi`` flag turns the spec-011 sleep stage off over a file value."""
    base = ScanConfig.model_validate({"injection": {"time_based_cmdi": True}})
    assert (
        base.with_overrides(injection={"time_based_cmdi": False}).injection.time_based_cmdi is False
    )


def test_xxe_override_wins_over_file() -> None:
    """The ``--xxe`` flag turns the spec-012 XXE step on over an off file value."""
    base = ScanConfig.model_validate({"injection": {"xxe": False}})
    assert base.with_overrides(injection={"xxe": True}).injection.xxe is True


def test_file_upload_override_wins_over_file() -> None:
    """The ``--file-upload`` flag turns the spec-014 upload pass on over an off file value."""
    base = ScanConfig.model_validate({"injection": {"file_upload": False}})
    assert base.with_overrides(injection={"file_upload": True}).injection.file_upload is True


# ---------------------------------------------------------------------------
# The [deps] section (spec 010)
# ---------------------------------------------------------------------------


def test_deps_section_defaults_and_round_trips(tmp_path: Path) -> None:
    """``[deps]`` OSV settings default off / 10s / api.osv.dev and round-trip through TOML."""
    defaults = ScanConfig().deps
    assert defaults.osv_online is False
    assert defaults.osv_timeout_s == 10.0
    assert defaults.osv_base_url == "https://api.osv.dev"
    assert ScanConfig.model_validate(ScanConfig().model_dump()).deps == defaults
    path = tmp_path / "webvigil.toml"
    path.write_text(
        '[deps]\nosv_online = true\nosv_timeout_s = 4.5\nosv_base_url = "http://osv.test"\n',
        "utf-8",
    )
    loaded = ScanConfig.load(path).deps
    assert loaded.osv_online is True
    assert loaded.osv_timeout_s == 4.5
    assert loaded.osv_base_url == "http://osv.test"


def test_unknown_deps_key_is_rejected(tmp_path: Path) -> None:
    """An unknown key under ``[deps]`` is a :class:`ConfigError`."""
    path = tmp_path / "webvigil.toml"
    path.write_text("[deps]\nosv_online = true\nnope = 1\n", "utf-8")
    with pytest.raises(ConfigError):
        ScanConfig.load(path)


def test_osv_online_override_wins_over_file() -> None:
    """The ``osv_online`` opt-in can be enabled by an override over an off file value."""
    base = ScanConfig.model_validate({"deps": {"osv_online": False}})
    assert base.with_overrides(deps={"osv_online": True}).deps.osv_online is True


# ---------------------------------------------------------------------------
# The [auth] section (spec 007, spec 013)
# ---------------------------------------------------------------------------


def test_auth_cookies_default_empty_and_round_trip(tmp_path: Path) -> None:
    """``[auth] cookies`` defaults empty and its ``as_header`` join round-trips from TOML."""
    assert ScanConfig().auth.cookies == []
    assert ScanConfig().auth.as_header == ""
    path = tmp_path / "webvigil.toml"
    path.write_text("[auth]\ncookies = ['session=abc', 'csrf=xyz']\n", "utf-8")
    loaded = ScanConfig.load(path).auth
    assert loaded.cookies == ["session=abc", "csrf=xyz"]
    assert loaded.as_header == "session=abc; csrf=xyz"


@pytest.mark.parametrize("bad", ["sessionabc", "=value", "   =v"])
def test_auth_cookie_without_a_valid_pair_is_rejected(tmp_path: Path, bad: str) -> None:
    """A cookie string that is not a ``name=value`` pair is rejected at load time."""
    path = tmp_path / "webvigil.toml"
    path.write_text(f"[auth]\ncookies = ['{bad}']\n", "utf-8")
    with pytest.raises(ConfigError):
        ScanConfig.load(path)


def test_unknown_auth_key_is_rejected(tmp_path: Path) -> None:
    """A key under ``[auth]`` that is neither ``cookies`` nor ``headers`` is rejected."""
    path = tmp_path / "webvigil.toml"
    path.write_text("[auth]\ncookies = []\ntokens = ['x']\n", "utf-8")
    with pytest.raises(ConfigError):
        ScanConfig.load(path)


def test_auth_cookies_override_replaces_the_file_list() -> None:
    """A ``cookies`` override replaces the whole file list rather than merging."""
    base = ScanConfig.model_validate({"auth": {"cookies": ["a=1", "b=2"]}})
    merged = base.with_overrides(auth={"cookies": ["c=3"]})
    assert merged.auth.cookies == ["c=3"]


def test_auth_headers_default_empty_and_round_trip(tmp_path: Path) -> None:
    """``[auth] headers`` defaults empty; ``header_pairs`` splits on the first colon (spec 013)."""
    assert ScanConfig().auth.headers == []
    assert ScanConfig().auth.header_pairs == ()
    path = tmp_path / "webvigil.toml"
    path.write_text(
        "[auth]\nheaders = ['Authorization: Bearer a:b:c', 'X-Tenant: acme']\n", "utf-8"
    )
    loaded = ScanConfig.load(path).auth
    assert loaded.header_pairs == (("Authorization", "Bearer a:b:c"), ("X-Tenant", "acme"))


@pytest.mark.parametrize("bad", ["no-colon-here", ": value", "   : v", "Host: evil.example"])
def test_auth_header_that_is_malformed_or_reserved_is_rejected(tmp_path: Path, bad: str) -> None:
    """A header with no ``:``, an empty name, or a reserved name is rejected at load time."""
    path = tmp_path / "webvigil.toml"
    path.write_text(f"[auth]\nheaders = ['{bad}']\n", "utf-8")
    with pytest.raises(ConfigError):
        ScanConfig.load(path)


def test_auth_headers_override_replaces_the_file_list() -> None:
    """A ``headers`` override replaces the whole file list rather than merging (spec 013)."""
    base = ScanConfig.model_validate({"auth": {"headers": ["Authorization: Bearer old"]}})
    merged = base.with_overrides(auth={"headers": ["X-API-Key: new"]})
    assert merged.auth.headers == ["X-API-Key: new"]


# ---------------------------------------------------------------------------
# Misc [scan] toggles
# ---------------------------------------------------------------------------


def test_submit_forms_defaults_on_and_round_trips(tmp_path: Path) -> None:
    """``[scan] submit_forms`` defaults on and can be turned off from a TOML file."""
    assert ScanConfig().scan.submit_forms is True
    path = tmp_path / "webvigil.toml"
    path.write_text("[scan]\nsubmit_forms = false\n", "utf-8")
    assert ScanConfig.load(path).scan.submit_forms is False


def test_openapi_defaults_off_and_round_trips(tmp_path: Path) -> None:
    """``[scan] openapi`` defaults to ``None`` and its path / cap round-trip (spec 013)."""
    assert ScanConfig().scan.openapi is None
    assert ScanConfig().scan.openapi_max_operations == 150
    path = tmp_path / "webvigil.toml"
    path.write_text("[scan]\nopenapi = 'openapi.json'\nopenapi_max_operations = 40\n", "utf-8")
    loaded = ScanConfig.load(path).scan
    assert loaded.openapi == "openapi.json"
    assert loaded.openapi_max_operations == 40


def test_openapi_override_wins_over_file() -> None:
    """A ``scan.openapi`` override beats the file value (spec 013)."""
    base = ScanConfig.model_validate({"scan": {"openapi": "old.json"}})
    merged = base.with_overrides(scan={"openapi": "https://target.example/openapi.json"})
    assert merged.scan.openapi == "https://target.example/openapi.json"
