"""
The destination policy (spec 026): the table of destination cases, ``keeps_data``,
``without_credentials``, ``is_target_host`` and ``is_public_name`` — RF-02, RF-06, RF-10, ADR-5.

The table states, for each ``(target, scope, url)``, whether the URL may be requested and whether it
may carry the scan's credentials, and asserts the same answer from the policy and from the rules
in ``Target``. Nothing is mocked: the policy and the vendored Public Suffix List are pure.
"""

from __future__ import annotations

import pytest

from webvigil.core import Scope, Target, destination
from webvigil.core.destination import (
    CREDENTIAL_HEADERS,
    SPECIAL_USE_LABELS,
    is_public_name,
    is_target_host,
    keeps_data,
    may_carry_credentials,
    may_request,
    without_credentials,
)
from webvigil.core.suffixes import load_rules, parse_rules

_HOST = Scope.HOST
_SUB = Scope.SUBDOMAINS

# ---------------------------------------------------------------------------
# The table of destination cases (RF-02)
# ---------------------------------------------------------------------------

# (target, scope, url, may_request, may_carry_credentials)
_CASES: list[tuple[str, Scope, str, bool, bool]] = [
    # scheme, and the https upgrade in both directions
    ("https://example.com/", _HOST, "https://example.com/a", True, True),
    ("https://example.com/", _HOST, "http://example.com/a", True, False),
    ("http://example.com/", _HOST, "https://example.com/a", True, True),
    ("http://example.com/", _HOST, "http://example.com/a", True, True),
    ("http://example.com:8080/", _HOST, "https://example.com/a", False, False),
    ("https://example.com/", _HOST, "ftp://example.com/a", False, False),
    ("https://example.com/", _HOST, "javascript:alert(1)", False, False),
    # host case and a trailing dot
    ("https://example.com/", _HOST, "https://EXAMPLE.com/a", True, True),
    ("https://Example.COM/", _HOST, "https://example.com/a", True, True),
    ("https://example.com/", _HOST, "https://example.com./a", False, False),
    # explicit and default ports, and the 80/443 pair
    ("https://example.com/", _HOST, "https://example.com:443/a", True, True),
    ("https://example.com/", _HOST, "https://example.com:8443/a", False, False),
    ("https://example.com/", _HOST, "http://example.com:80/a", True, False),
    ("https://example.com/", _HOST, "http://example.com:8080/a", False, False),
    ("http://example.com/", _HOST, "https://example.com:8443/a", False, False),
    ("http://example.com:8080/", _HOST, "http://example.com:8080/a", True, True),
    ("http://example.com:8080/", _HOST, "http://example.com/a", False, False),
    ("https://example.com:8443/", _HOST, "http://example.com:8443/a", True, False),
    # sibling, parent and deeper subdomains under each scope
    ("https://example.com/", _HOST, "https://api.example.com/", False, False),
    ("https://example.com/", _SUB, "https://api.example.com/", True, False),
    ("https://example.com/", _SUB, "https://a.b.example.com/", True, False),
    ("https://example.com/", _SUB, "http://api.example.com/", True, False),
    ("https://example.com/", _SUB, "https://api.example.com:8443/", False, False),
    ("https://example.com/", _SUB, "https://notexample.com/", False, False),
    ("https://example.com/", _SUB, "https://example.org/", False, False),
    ("https://app.example.com/", _HOST, "https://example.com/", False, False),
    ("https://app.example.com/", _HOST, "https://other.example.com/", False, False),
    ("https://app.example.com/", _SUB, "https://example.com/", True, False),
    ("https://app.example.com/", _SUB, "https://other.example.com/", True, False),
    ("https://app.example.com/", _SUB, "https://deep.app.example.com/", True, False),
    ("https://app.example.com/", _SUB, "https://app.example.com/", True, True),
    ("https://example.co.uk/", _SUB, "https://api.example.co.uk/", True, False),
    ("https://example.co.uk/", _SUB, "https://other.co.uk/", False, False),
    # IP literals, a one-label host, a public-suffix target
    ("http://10.0.0.5:8080/", _SUB, "http://10.0.0.5:8080/a", True, True),
    ("http://10.0.0.5:8080/", _SUB, "http://1.10.0.0.5:8080/", False, False),
    ("http://10.0.0.5:8080/", _SUB, "http://10.0.0.6:8080/", False, False),
    ("http://[::1]:8000/", _SUB, "http://[::1]:8000/a", True, True),
    ("http://[::1]:8000/", _SUB, "http://[::2]:8000/", False, False),
    ("http://[::1]:8000/", _SUB, "http://[0:0:0:0:0:0:0:1]:8000/", False, False),
    ("http://app:8000/", _SUB, "http://app:8000/a", True, True),
    ("http://app:8000/", _SUB, "http://evil.app:8000/", False, False),
    ("https://github.io/", _SUB, "https://github.io/a", True, True),
    ("https://github.io/", _SUB, "https://alice.github.io/", False, False),
    ("https://www.alice.github.io/", _SUB, "https://api.alice.github.io/", True, False),
    ("https://www.alice.github.io/", _SUB, "https://bob.github.io/", False, False),
    # malformed URLs, a bare host[:port], userinfo
    ("https://example.com/", _HOST, "", False, False),
    ("https://example.com/", _HOST, "not a url", False, False),
    ("https://example.com/", _HOST, "https://example.com:99999/", False, False),
    ("https://example.com/", _HOST, "https://example.com:port/", False, False),
    ("https://example.com/", _HOST, "https://[::1/", False, False),
    ("https://example.com/", _HOST, "https:///a", False, False),
    ("https://example.com/", _HOST, "example.com", True, True),
    ("https://example.com/", _HOST, "example.com:8443", False, False),
    ("https://example.com/", _HOST, "https://user:pw@example.com/a", True, True),
    ("https://example.com/", _HOST, "https://example.com@evil.example/a", False, False),
    ("https://example.com/", _SUB, "https://example.com.evil.example/", False, False),
]


@pytest.mark.parametrize(
    ("raw", "scope", "url", "request_expected", "credentials_expected"),
    _CASES,
    ids=[f"{raw}|{scope}|{url}" for raw, scope, url, _r, _c in _CASES],
)
def test_the_policy_and_the_rules_give_the_tables_answer(
    raw: str, scope: Scope, url: str, request_expected: bool, credentials_expected: bool
) -> None:
    """Each row: the stated answers, from the policy and from the rules of ``Target`` alike."""
    target = Target.parse(raw, scope=scope)
    assert may_request(target, url) is request_expected
    assert may_carry_credentials(target, url) is credentials_expected
    assert target.in_scope(url) is request_expected
    assert target.carries_credentials(url) is credentials_expected


def test_the_table_has_rows_where_the_two_rules_differ() -> None:
    """The table could not pass with one rule standing in for the other (RF-10)."""
    differ = [row for row in _CASES if row[3] != row[4]]
    assert len(differ) >= 10
    assert all(request and not credentials for _t, _s, _u, request, credentials in differ)


def test_credentials_never_go_where_a_request_may_not() -> None:
    """Over the table, every URL that may carry the credentials may also be requested."""
    for raw, scope, url, request, credentials in _CASES:
        assert request or not credentials, (raw, scope, url)


# ---------------------------------------------------------------------------
# keeps_data
# ---------------------------------------------------------------------------

_TARGET = Target.parse("https://example.com/", scope=Scope.SUBDOMAINS)
_ORIGIN = "https://example.com/login"  # may carry the credentials
_SIBLING = "https://api.example.com/next"  # in scope, may not carry them


@pytest.mark.parametrize(
    ("current", "following", "credentialed", "expected"),
    [
        (_ORIGIN, _ORIGIN, True, True),
        (_ORIGIN, _SIBLING, True, False),
        (_SIBLING, _ORIGIN, True, True),
        (_SIBLING, _SIBLING, True, True),
        (_ORIGIN, _ORIGIN, False, True),
        (_ORIGIN, _SIBLING, False, True),
        (_SIBLING, _ORIGIN, False, True),
        (_SIBLING, _SIBLING, False, True),
    ],
)
def test_data_is_withheld_only_from_the_origin_to_where_credentials_may_not_go(
    current: str, following: str, credentialed: bool, expected: bool
) -> None:
    """A credentialed request's data does not follow a redirect off the credential origin."""
    assert keeps_data(_TARGET, current, following, credentialed=credentialed) is expected


def test_data_is_withheld_from_the_origin_to_its_plain_http() -> None:
    """Under ``--scope host`` too: plain ``http`` of an ``https`` target is in scope but refused."""
    target = Target.parse("https://example.com/")
    origin, plain = "https://example.com/a", "http://example.com/b"
    assert not keeps_data(target, origin, plain, credentialed=True)
    assert keeps_data(target, origin, "https://example.com/b", credentialed=True)


# ---------------------------------------------------------------------------
# without_credentials
# ---------------------------------------------------------------------------

_HEADERS = {
    "Cookie": "sid=1",
    "AUTHORIZATION": "Bearer t",
    "X-Api-Key": "k",
    "X-Other-Token": "o",
    "Accept": "text/html",
}


def test_the_credential_headers_are_dropped_for_a_refused_url() -> None:
    """``Cookie``, ``Authorization`` and a configured ``[auth]`` name go, in any case."""
    kept = without_credentials(_TARGET, _HEADERS, _SIBLING, auth_names=["x-API-key"])
    assert kept == {"X-Other-Token": "o", "Accept": "text/html"}


def test_every_header_is_kept_for_the_origin() -> None:
    """The positive control: the same headers reach the credential origin whole."""
    kept = without_credentials(_TARGET, _HEADERS, _ORIGIN, auth_names=["x-API-key"])
    assert kept == _HEADERS
    assert kept is not _HEADERS  # a copy: the caller's mapping is never the one sent on


def test_an_unconfigured_custom_header_is_not_a_credential() -> None:
    """Only the fixed names and the configured ones are dropped."""
    kept = without_credentials(_TARGET, _HEADERS, _SIBLING, auth_names=[])
    assert kept == {"X-Api-Key": "k", "X-Other-Token": "o", "Accept": "text/html"}


def test_the_callers_headers_are_left_untouched() -> None:
    """Filtering returns a new mapping; the caller's stays as it was."""
    headers = dict(_HEADERS)
    without_credentials(_TARGET, headers, _SIBLING, auth_names=["x-api-key"])
    assert headers == _HEADERS


@pytest.mark.parametrize("url", [_ORIGIN, _SIBLING])
def test_no_headers_pass_through(url: str) -> None:
    """``None`` stays ``None`` and an empty mapping stays empty, for either URL."""
    assert without_credentials(_TARGET, None, url, auth_names=["x-api-key"]) is None
    assert without_credentials(_TARGET, {}, url, auth_names=["x-api-key"]) == {}


def test_the_fixed_credential_headers() -> None:
    """The names every scan treats as a credential, compared in lower case."""
    assert frozenset({"cookie", "authorization"}) == CREDENTIAL_HEADERS


# ---------------------------------------------------------------------------
# is_target_host
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "url", "expected"),
    [
        ("https://example.com:8443/", "https://example.com:8443/a", True),
        ("https://example.com:8443/", "http://EXAMPLE.com/a", True),
        ("https://example.com/", "https://api.example.com/", False),
        ("https://example.com/", "https://example.com.evil.example/", False),
        ("http://[::1]:8000/", "http://[::1]:9000/", True),
        ("https://example.com/", "/relative/path", False),
        ("https://example.com/", "", False),
        ("https://example.com/", "https://[::1/", False),
    ],
)
def test_is_target_host_compares_the_host_alone(raw: str, url: str, expected: bool) -> None:
    """The host decides, whatever the scheme and port; no host or a malformed one is ``False``."""
    assert is_target_host(Target.parse(raw), url) is expected


# ---------------------------------------------------------------------------
# is_public_name (ADR-5)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "app.example.com",
        "example.co.uk",
        "www.alice.github.io",
        "xn--bcher-kva.com",
        "x.y.ck",  # ``ck`` is listed only as the base of ``*.ck``
        "APP.Example.COM.",
    ],
)
def test_a_name_under_a_listed_top_level_label_is_public(host: str) -> None:
    """A dotted name whose top-level label is on the list, and not special-use."""
    assert is_public_name(host)


@pytest.mark.parametrize(
    "host",
    [
        "app.local",
        "app.internal",
        "svc.cluster.local",
        "x.home.arpa",
        "x.onion",
        "x.test",
        "x.localhost",
        "x.alt",
        "x.invalid",
        "x.example",
        "app.notalistedlabel",
        "app",
        "localhost",
        "10.0.0.5",
        "::1",
        "fd00::1",
        "",
        ".",
        "a..com",
    ],
)
def test_lab_cluster_special_use_and_address_names_are_not_public(host: str) -> None:
    """Special-use and unlisted labels, one label, IP literals and malformed names."""
    assert not is_public_name(host)


@pytest.mark.parametrize("label", sorted(SPECIAL_USE_LABELS))
def test_a_special_use_label_stays_private_on_a_list_that_carries_it(
    monkeypatch: pytest.MonkeyPatch, label: str
) -> None:
    """A list update that adds a special-use label, or a numeric rule, changes no answer."""
    rules = parse_rules("\n".join([*SPECIAL_USE_LABELS, "5", "com"]))
    monkeypatch.setattr(destination, "load_rules", lambda: rules)
    assert not is_public_name(f"app.{label}")
    assert not is_public_name("10.0.0.5")
    assert not is_public_name("::ffff:10.0.0.5")
    assert is_public_name("app.example.com")  # the positive control: the stub list is the one read


def test_some_special_use_labels_are_on_the_list() -> None:
    """Why the labels are checked explicitly: the list does carry ``onion`` and ``arpa``."""
    rules = load_rules()
    assert {"onion", "arpa"} <= SPECIAL_USE_LABELS
    assert "onion" in rules.exact
    assert "arpa" in rules.exact
