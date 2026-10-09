"""
Config model, TOML loading, and CLI-override precedence — RF-26.

Each section follows the same shape: assert the defaults and check that a ``webvigil.toml``
under ``tmp_path`` round-trips through :meth:`ScanConfig.load`. Unknown keys and misspelled
sections must raise :class:`ConfigError` rather than being silently dropped.

Audited under issue #101: the per-key "an override beats the file" tests were the same
``with_overrides`` mechanism eight times; the generic one stays here and each flag's real wiring is
asserted end to end in ``test_cli.py::test_flags_override_the_config_file``. The per-section
"unknown key" and "invalid value" tests became one table each.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from webvigil.core import ConfigError, ScanConfig
from webvigil.core.findings import ScanMode


def _write(tmp_path: Path, toml: str) -> Path:
    """
    Args:
        tmp_path (Path): A temporary directory.
        toml (str): The config file's text.

    Returns:
        Path: The ``webvigil.toml`` written under ``tmp_path``.
    """
    path = tmp_path / "webvigil.toml"
    path.write_text(toml, "utf-8")
    return path


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
    path = _write(
        tmp_path,
        "[scan]\nmode = 'active'\nmax_pages = 5\n\n[active]\nauthorized_by = 'Jane / #1'\n",
    )
    config = ScanConfig.load(path)
    assert config.scan.mode is ScanMode.ACTIVE
    assert config.scan.max_pages == 5
    assert config.active is not None and config.active.authorized_by == "Jane / #1"


def test_web_section_is_tolerated_as_passthrough(tmp_path: Path) -> None:
    """The ``[web]`` table is kept verbatim for the API to read, not validated here."""
    path = _write(tmp_path, "[scan]\nmax_pages = 7\n\n[web]\nport = 9000\ndatabase_path = 'x.db'\n")
    config = ScanConfig.load(path)
    assert config.scan.max_pages == 7
    assert config.web == {"port": 9000, "database_path": "x.db"}


def test_a_missing_file_is_a_config_error(tmp_path: Path) -> None:
    """Pointing ``load`` at a file that does not exist is a :class:`ConfigError`."""
    with pytest.raises(ConfigError):
        ScanConfig.load(tmp_path / "absent.toml")


def test_overrides_replace_their_key_and_leave_the_rest(tmp_path: Path) -> None:
    """An override replaces its key, an untouched section stays, an empty override is a no-op."""
    base = ScanConfig.model_validate({"scan": {"max_pages": 5}, "http": {"delay_ms": 100}})
    merged = base.with_overrides(scan={"max_pages": 99}, http={})
    assert merged.scan.max_pages == 99
    assert merged.http.delay_ms == 100  # untouched section stays
    assert ScanConfig().with_overrides(scan={}) == ScanConfig()  # not a reset to defaults


# (a table that names a section and a key it does not have — each must be rejected)
_UNKNOWN_KEYS = [
    "[scan]\nnope = true\n",
    "[disclosure]\nprobe = true\nnope = 1\n",
    "[injection]\nrequest_budget = 40\nnope = 1\n",
    "[deps]\nosv_online = true\nnope = 1\n",
    "[auth]\ncookies = []\ntokens = ['x']\n",
    "[scna]\nmax_pages = 7\n",  # a misspelled section name
    "[auth.login]\nurl = 'http://x/login'\nusername = 'u'\nnope = 1\n",
]

# (a table of values the model must refuse at load time)
_INVALID_VALUES = [
    "[auth]\ncookies = ['sessionabc']\n",
    "[auth]\ncookies = ['=value']\n",
    "[auth]\ncookies = ['   =v']\n",
    "[auth]\nheaders = ['no-colon-here']\n",
    "[auth]\nheaders = [': value']\n",
    "[auth]\nheaders = ['   : v']\n",
    "[auth]\nheaders = ['Host: evil.example']\n",  # a reserved header name
    "[scan]\nmax_post_submissions = 0\n",
    "[scan]\nhar_max_operations = 0\n",  # spec 021
    # spec 019: the login table
    "[auth.login]\nusername = 'u'\n",  # no url
    "[auth.login]\nurl = 'http://x/login'\n",  # no username
    "[auth.login]\nurl = 'http://x/login'\nusername = 'u'\npassword = 's3cret'\n",
    "[auth.login]\nurl = 'http://x/login'\nusername = 'u'\nmax_relogins = 11\n",
    "[auth.login]\nurl = 'http://x/login'\nusername = 'u'\nmax_relogins = -1\n",
    "[auth.login]\nurl = 'http://x/login'\nusername = 'u'\nform_index = -1\n",
    "[auth.login]\nurl = 'http://x/login'\nusername = 'u'\nextra_fields = ['novalue']\n",
    "[auth.login]\nurl = 'http://x/login'\nusername = 'u'\nlogged_in_marker = '('\n",
]


def test_unknown_keys_and_misspelled_sections_are_rejected(tmp_path: Path) -> None:
    """An unknown key in any section, or a misspelled section, is a :class:`ConfigError`."""
    for toml in _UNKNOWN_KEYS:
        with pytest.raises(ConfigError):
            ScanConfig.load(_write(tmp_path, toml))


def test_invalid_values_are_rejected_at_load_time(tmp_path: Path) -> None:
    """A malformed cookie or header, a reserved header name or a non-positive cap is rejected."""
    for toml in _INVALID_VALUES:
        with pytest.raises(ConfigError):
            ScanConfig.load(_write(tmp_path, toml))


# ---------------------------------------------------------------------------
# Section defaults and TOML round-trips
# ---------------------------------------------------------------------------


def test_scan_and_disclosure_keys_default_and_round_trip(tmp_path: Path) -> None:
    """``probe``, ``submit_forms``, the OpenAPI keys and the POST-crawl keys load from TOML."""
    defaults = ScanConfig()
    assert defaults.disclosure.probe is False
    assert defaults.scan.submit_forms is True
    assert defaults.scan.openapi is None
    assert defaults.scan.openapi_max_operations == 150
    assert defaults.scan.submit_post_forms is False
    assert defaults.scan.max_post_submissions == 25
    assert defaults.scan.har is None
    assert defaults.scan.har_max_operations == 150
    path = _write(
        tmp_path,
        "[disclosure]\nprobe = true\n\n[scan]\nsubmit_forms = false\n"
        "openapi = 'openapi.json'\nopenapi_max_operations = 40\n"
        "submit_post_forms = true\nmax_post_submissions = 3\n"
        "har = 'traffic.har'\nhar_max_operations = 12\n",
    )
    loaded = ScanConfig.load(path)
    assert loaded.disclosure.probe is True
    assert loaded.scan.submit_forms is False
    assert loaded.scan.openapi == "openapi.json"
    assert loaded.scan.openapi_max_operations == 40
    assert loaded.scan.submit_post_forms is True
    assert loaded.scan.max_post_submissions == 3
    assert loaded.scan.har == "traffic.har"
    assert loaded.scan.har_max_operations == 12


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
    assert defaults.csrf_confirm is False
    assert defaults.envelope_url_sample == 15
    path = _write(
        tmp_path,
        "[injection]\nrequest_budget = 40\ntime_based_sqli = false\n"
        "time_based_cmdi = false\nstored_xss = true\nxxe = true\nfile_upload = true\n"
        "csrf_confirm = true\n",
    )
    loaded = ScanConfig.load(path).injection
    assert loaded.request_budget == 40
    assert loaded.time_based_sqli is False
    assert loaded.time_based_cmdi is False
    assert loaded.stored_xss is True
    assert loaded.xxe is True
    assert loaded.file_upload is True
    assert loaded.csrf_confirm is True


def test_deps_section_defaults_and_round_trips(tmp_path: Path) -> None:
    """``[deps]`` OSV settings default off / 10s / api.osv.dev and round-trip through TOML."""
    defaults = ScanConfig().deps
    assert defaults.osv_online is False
    assert defaults.osv_timeout_s == 10.0
    assert defaults.osv_base_url == "https://api.osv.dev"
    assert ScanConfig.model_validate(ScanConfig().model_dump()).deps == defaults
    path = _write(
        tmp_path,
        '[deps]\nosv_online = true\nosv_timeout_s = 4.5\nosv_base_url = "http://osv.test"\n',
    )
    loaded = ScanConfig.load(path).deps
    assert loaded.osv_online is True
    assert loaded.osv_timeout_s == 4.5
    assert loaded.osv_base_url == "http://osv.test"


# ---------------------------------------------------------------------------
# The [auth] section (spec 007, spec 013)
# ---------------------------------------------------------------------------


def test_auth_cookies_default_empty_and_round_trip(tmp_path: Path) -> None:
    """``[auth] cookies`` defaults empty and its ``as_header`` join round-trips from TOML."""
    assert ScanConfig().auth.cookies == []
    assert ScanConfig().auth.as_header == ""
    loaded = ScanConfig.load(
        _write(tmp_path, "[auth]\ncookies = ['session=abc', 'csrf=xyz']\n")
    ).auth
    assert loaded.cookies == ["session=abc", "csrf=xyz"]
    assert loaded.as_header == "session=abc; csrf=xyz"


def test_auth_headers_default_empty_and_round_trip(tmp_path: Path) -> None:
    """``[auth] headers`` defaults empty; ``header_pairs`` splits on the first colon (spec 013)."""
    assert ScanConfig().auth.headers == []
    assert ScanConfig().auth.header_pairs == ()
    path = _write(tmp_path, "[auth]\nheaders = ['Authorization: Bearer a:b:c', 'X-Tenant: acme']\n")
    loaded = ScanConfig.load(path).auth
    assert loaded.header_pairs == (("Authorization", "Bearer a:b:c"), ("X-Tenant", "acme"))


def test_auth_list_overrides_replace_the_file_list() -> None:
    """A ``cookies`` / ``headers`` override replaces the whole file list rather than merging."""
    base = ScanConfig.model_validate(
        {"auth": {"cookies": ["a=1", "b=2"], "headers": ["Authorization: Bearer old"]}}
    )
    merged = base.with_overrides(auth={"cookies": ["c=3"], "headers": ["X-API-Key: new"]})
    assert merged.auth.cookies == ["c=3"]
    assert merged.auth.headers == ["X-API-Key: new"]


def test_auth_login_defaults_helpers_and_round_trip(tmp_path: Path) -> None:
    """``[auth.login]`` defaults, parsed extras and the ``configured`` / ``has_session`` flags."""
    assert ScanConfig().auth.login is None
    assert not ScanConfig().auth.configured
    assert not ScanConfig().auth.has_session

    toml = (
        "[auth.login]\nurl = 'http://x/signin'\nusername = 'scanner'\n"
        "extra_fields = ['tenant=acme', 'token=a=b']\ncheck_url = 'http://x/account'\n"
    )
    auth = ScanConfig.load(_write(tmp_path, toml)).auth
    assert auth.login is not None
    assert auth.login.password_env == "WEBVIGIL_LOGIN_PASSWORD"
    assert auth.login.max_relogins == 3
    assert auth.login.extra_pairs == (("tenant", "acme"), ("token", "a=b"))
    # a login is a credential and a session; a header alone is a credential but no session
    assert auth.configured and auth.has_session
    headers_only = ScanConfig.model_validate({"auth": {"headers": ["X-Key: v"]}}).auth
    assert headers_only.configured and not headers_only.has_session


def test_the_login_password_never_enters_the_config_dump() -> None:
    """The password has no field, so no dump or merge of the config can carry it (RF-02)."""
    cfg = ScanConfig.model_validate({"auth": {"login": {"url": "http://x/s", "username": "u"}}})
    assert "password" not in cfg.model_dump()["auth"]["login"]
    assert "password_env" in cfg.model_dump()["auth"]["login"]


# ---------------------------------------------------------------------------
# The [session] section and [auth.login] logout_url (spec 020)
# ---------------------------------------------------------------------------


def test_session_section_defaults_ranges_and_round_trip(tmp_path: Path) -> None:
    """``[session]`` defaults to everything off, 10 samples, and keeps its range at 3..20."""
    defaults = ScanConfig().session
    assert (defaults.sample_ids, defaults.sample_count, defaults.test_logout) == (False, 10, False)

    toml = "[session]\nsample_ids = true\nsample_count = 5\ntest_logout = true\n"
    loaded = ScanConfig.load(_write(tmp_path, toml)).session
    assert (loaded.sample_ids, loaded.sample_count, loaded.test_logout) == (True, 5, True)

    for bad in ("sample_count = 2", "sample_count = 21", "sample_count = 0", "nope = 1"):
        with pytest.raises(ConfigError):
            ScanConfig.load(_write(tmp_path, f"[session]\n{bad}\n"))


def test_the_login_table_takes_a_logout_url(tmp_path: Path) -> None:
    """``[auth.login] logout_url`` is optional and round-trips."""
    toml = "[auth.login]\nurl = 'http://x/in'\nusername = 'u'\nlogout_url = 'http://x/out'\n"
    assert ScanConfig.load(_write(tmp_path, toml)).auth.login.logout_url == "http://x/out"  # type: ignore[union-attr]
    assert (
        ScanConfig.model_validate(
            {"auth": {"login": {"url": "http://x/in", "username": "u"}}}
        ).auth.login.logout_url
        is None
    )  # type: ignore[union-attr]
