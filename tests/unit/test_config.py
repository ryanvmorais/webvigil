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
from webvigil.core.secrets import Secret, SecretKind


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


def test_the_web_section_is_accepted_and_keeps_no_value(tmp_path: Path) -> None:
    """The ``[web]`` table loads, and none of its values stays in the config (spec 024, RF-06)."""
    toml = "[scan]\nmax_pages = 7\n\n[web]\nport = 9000\nsession_secret = 'w3b-s1gning-k3y'\n"
    config = ScanConfig.load(_write(tmp_path, toml))
    assert config.scan.max_pages == 7  # the rest of the file was read
    assert config.web == {}
    assert "w3b-s1gning-k3y" not in repr(config) + config.model_dump_json()
    assert ScanConfig().web is None  # no table, nothing
    with pytest.raises(ConfigError, match="web"):  # still a table, or nothing
        ScanConfig.model_validate_or_raise({"web": "not a table"})


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


def test_the_time_based_delay_is_at_least_two_seconds(tmp_path: Path) -> None:
    """
    Two seconds is accepted; less is refused.

    A time-based hit needs ``delay - 1`` seconds over the slower of the control and the baseline.
    At one second or less that margin is zero or negative, so a target that never waits would be
    reported as injectable.
    """
    loaded = ScanConfig.load(_write(tmp_path, "[injection]\ntime_based_delay_s = 2\n"))
    assert loaded.injection.time_based_delay_s == 2
    for bad in (1, 0, -3):
        with pytest.raises(ConfigError):
            ScanConfig.load(_write(tmp_path, f"[injection]\ntime_based_delay_s = {bad}\n"))


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


def _shown(secrets: list[Secret]) -> list[tuple[SecretKind, str | None, str]]:
    """
    Args:
        secrets (list[Secret]): Parsed ``[auth]`` entries.

    Returns:
        list[tuple[SecretKind, str | None, str]]: Each entry's kind, name and value.
    """
    return [(secret.kind, secret.name, secret.reveal()) for secret in secrets]


def test_auth_cookies_default_empty_and_parse_into_named_secrets(tmp_path: Path) -> None:
    """Each ``[auth] cookies`` entry is a named ``COOKIE`` secret (spec 024, RF-04)."""
    assert ScanConfig().auth.cookies == []
    toml = "[auth]\ncookies = ['session=abc', 'csrf=x=y', ' pad = v ']\n"
    loaded = ScanConfig.load(_write(tmp_path, toml)).auth
    assert all(isinstance(cookie, Secret) for cookie in loaded.cookies)
    # the value keeps any '=' after the first; around the first, the entry is kept as written
    assert _shown(loaded.cookies) == [
        (SecretKind.COOKIE, "session", "abc"),
        (SecretKind.COOKIE, "csrf", "x=y"),
        (SecretKind.COOKIE, "pad ", " v"),
    ]


def test_auth_headers_default_empty_and_parse_into_named_secrets(tmp_path: Path) -> None:
    """``header_pairs`` splits on the first colon (spec 013) and holds ``HEADER`` secrets."""
    assert ScanConfig().auth.headers == []
    assert ScanConfig().auth.header_pairs == ()
    path = _write(
        tmp_path, "[auth]\nheaders = ['Authorization: Bearer a:b:c', ' X-Tenant :acme ']\n"
    )
    loaded = ScanConfig.load(path).auth
    assert _shown(loaded.headers) == [
        (SecretKind.HEADER, "Authorization", "Bearer a:b:c"),
        (SecretKind.HEADER, "X-Tenant", "acme"),
    ]
    assert [(name, value.reveal()) for name, value in loaded.header_pairs] == [
        ("Authorization", "Bearer a:b:c"),
        ("X-Tenant", "acme"),
    ]


def test_auth_list_overrides_replace_the_file_list() -> None:
    """A ``cookies`` / ``headers`` override replaces the whole file list rather than merging."""
    base = ScanConfig.model_validate(
        {"auth": {"cookies": ["a=1", "b=2"], "headers": ["Authorization: Bearer old"]}}
    )
    merged = base.with_overrides(auth={"cookies": ["c=3"], "headers": ["X-API-Key: new"]})
    assert _shown(merged.auth.cookies) == [(SecretKind.COOKIE, "c", "3")]
    assert _shown(merged.auth.headers) == [(SecretKind.HEADER, "X-API-Key", "new")]


def test_a_config_validated_again_keeps_its_secrets() -> None:
    """An override of another section validates the dump again; its secrets pass unchanged."""
    base = ScanConfig.model_validate(
        {"auth": {"cookies": ["sid=abc"], "headers": ["Authorization: Bearer t"]}}
    )
    merged = base.with_overrides(scan={"max_pages": 3})
    assert merged.scan.max_pages == 3
    assert merged.auth.cookies[0] is base.auth.cookies[0]
    assert merged.auth.headers[0] is base.auth.headers[0]
    # a list mixing a kept secret and a new entry, as a Python caller may build it
    mixed = ScanConfig.model_validate({"auth": {"cookies": [*base.auth.cookies, "b=2"]}})
    assert _shown(mixed.auth.cookies) == [
        (SecretKind.COOKIE, "sid", "abc"),
        (SecretKind.COOKIE, "b", "2"),
    ]


def test_printing_or_dumping_the_config_shows_no_credential_value() -> None:
    """``repr``, ``str`` and a JSON-mode dump show the marker, never a cookie or header value."""
    cookie, token = "c00kie-VALUE", "t0ken-VALUE"
    cfg = ScanConfig.model_validate(
        {"auth": {"cookies": [f"sid={cookie}"], "headers": [f"Authorization: Bearer {token}"]}}
    )
    shown = repr(cfg) + str(cfg) + repr(cfg.auth) + cfg.model_dump_json()
    assert cookie not in shown and token not in shown
    assert "sid" in shown and "Authorization" in shown  # names are not secret
    # positive control: the values are held, and a plain-string dump would have shown them
    assert cfg.auth.cookies[0].reveal() == cookie
    assert token in cfg.auth.headers[0].reveal()


def test_an_auth_list_that_is_not_a_list_is_a_type_error() -> None:
    """A bare string for ``cookies`` or ``headers`` gets the list type error, not a parse."""
    for key in ("cookies", "headers"):
        with pytest.raises(ConfigError, match=f"auth.{key}: Input should be a valid list"):
            ScanConfig.model_validate_or_raise({"auth": {key: "a=b"}})


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


# ---------------------------------------------------------------------------
# Error messages never echo a value (a cookie, a header, a password)
# ---------------------------------------------------------------------------

_LEAK = "s3cr3t-LEAK-value"


@pytest.mark.parametrize(
    ("auth", "expected"),
    [
        ({"cookies": ["ok=1", _LEAK]}, "invalid cookie #2"),
        ({"headers": [f"Bearer {_LEAK}"]}, "invalid header #1"),
        (
            {"login": {"url": "http://x/in", "username": "u", "extra_fields": [_LEAK]}},
            "invalid extra field #1",
        ),
        ({"login": {"url": "http://x/in", "username": "u", "password": _LEAK}}, "password_env"),
        ({"cookies": [f"sid={_LEAK}", 7]}, "invalid cookie #2"),
        ({"headers": [f"Authorization: {_LEAK}", 7]}, "invalid header #2"),
    ],
)
def test_a_config_error_names_the_setting_but_never_its_value(
    auth: dict[str, object], expected: str
) -> None:
    """A malformed credential, or a password in the file, must not reach a terminal or CI log."""
    with pytest.raises(ConfigError) as caught:
        ScanConfig.model_validate_or_raise({"auth": auth})
    assert expected in str(caught.value)
    assert _LEAK not in str(caught.value)
    assert caught.value.__cause__ is None


_URL_USER = "markerUSER5d2e"
_URL_PASSWORD = "markerPASSWORD8c41"
_CREDENTIAL_URL = f"https://{_URL_USER}:{_URL_PASSWORD}@example.com/path"
_LOGIN = {"url": "https://example.com/in", "username": "u"}


@pytest.mark.parametrize(
    ("data", "location"),
    [
        ({"auth": {"login": {**_LOGIN, "url": _CREDENTIAL_URL}}}, "auth.login.url"),
        ({"auth": {"login": {**_LOGIN, "check_url": _CREDENTIAL_URL}}}, "auth.login.check_url"),
        ({"auth": {"login": {**_LOGIN, "logout_url": _CREDENTIAL_URL}}}, "auth.login.logout_url"),
        ({"scan": {"openapi": _CREDENTIAL_URL}}, "scan.openapi"),
        ({"deps": {"osv_base_url": _CREDENTIAL_URL}}, "deps.osv_base_url"),
    ],
)
def test_a_url_setting_with_a_credential_is_refused_by_name(
    data: dict[str, object], location: str
) -> None:
    """RF-09: a configuration error that names the setting and repeats no part of the URL."""
    with pytest.raises(ConfigError) as caught:
        ScanConfig.model_validate_or_raise(data)
    message = str(caught.value)
    assert f"{location}: Value error, a credential in a URL is not used" in message
    assert _URL_USER not in message and _URL_PASSWORD not in message


def test_a_file_path_or_a_relative_url_with_an_at_sign_is_accepted() -> None:
    """Positive control: no authority, no credential."""
    config = ScanConfig.model_validate_or_raise(
        {
            "scan": {"openapi": "specs/@team/openapi.json"},
            "auth": {"login": {**_LOGIN, "check_url": "/account/@me"}},
        }
    )
    assert config.scan.openapi == "specs/@team/openapi.json"
    assert config.auth.login is not None
    assert config.auth.login.check_url == "/account/@me"
