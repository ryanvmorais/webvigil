"""
Target parsing, URL normalization, and scope checks — RF-01, RF-02; the one-label and IPv6 hosts
of issue #191.

Nothing is mocked: parsing and scope are pure.
"""

from __future__ import annotations

import pytest

from webvigil.core import (
    InvalidTargetError,
    Scope,
    Target,
    is_valid_host,
    normalize_url,
    url_host,
)

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def test_scheme_defaults_to_https() -> None:
    """A bare host is parsed as ``https://``."""
    target = Target.parse("example.com")
    assert target.entry_url == "https://example.com/"
    assert target.origin == "https://example.com"
    assert target.host == "example.com"


def test_path_and_query_are_preserved_as_seed() -> None:
    """The seed keeps the path and query but drops the fragment."""
    target = Target.parse("https://example.com/app?a=1#frag")
    assert target.entry_url == "https://example.com/app?a=1"


@pytest.mark.parametrize("raw", ["", "not a url", "ftp://example.com", "mailto:a@b.c"])
def test_invalid_targets_raise(raw: str) -> None:
    """Empty input, non-URLs and non-HTTP schemes are rejected."""
    with pytest.raises(InvalidTargetError):
        Target.parse(raw)


@pytest.mark.parametrize(
    ("raw", "host", "origin"),
    [
        ("http://app:8000/", "app", "http://app:8000"),
        ("http://wiki/", "wiki", "http://wiki"),
        ("https://Api-Gateway/x", "api-gateway", "https://api-gateway"),
        ("http://localhost:8080", "localhost", "http://localhost:8080"),
        ("http://127.0.0.1:3000/", "127.0.0.1", "http://127.0.0.1:3000"),
        ("http://[::1]:8000/", "::1", "http://[::1]:8000"),
        ("https://[2001:db8::7]/", "2001:db8::7", "https://[2001:db8::7]"),
    ],
)
def test_one_label_and_ipv6_hosts_are_targets(raw: str, host: str, origin: str) -> None:
    """A service name and an IPv6 literal parse; the origin keeps the brackets."""
    target = Target.parse(raw)
    assert target.host == host
    assert target.origin == origin
    assert target.in_scope(f"{origin}/anything")


@pytest.mark.parametrize(
    "raw",
    [
        "http://-app/",  # a label cannot start with a hyphen
        "http://app-/",  # nor end with one
        "http://123/",  # all digits: a browser reads it as shorthand IPv4
        "http://app_name/",  # underscore is not a hostname character
        "http://[::1%25eth0]/",  # a zone id is local to one machine
        "http://[not:ipv6]/",
        "http://" + "a" * 64 + "/",  # a label is at most 63 characters
    ],
)
def test_malformed_hosts_are_still_refused(raw: str) -> None:
    """Widening what parses does not let a malformed host through."""
    with pytest.raises(InvalidTargetError):
        Target.parse(raw)


def test_is_valid_host_and_url_host() -> None:
    """The predicate takes ``urlsplit`` hostnames; brackets go only where a URL needs them."""
    assert is_valid_host("app") and is_valid_host("a.b.example") and is_valid_host("::1")
    assert not is_valid_host("") and not is_valid_host("42")
    assert url_host("::1") == "[::1]"
    assert url_host("app") == "app"
    assert url_host("10.0.0.1") == "10.0.0.1"


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def test_normalize_url_lowercases_and_drops_default_port_and_fragment() -> None:
    """Scheme and host lower-cased, default port and fragment dropped, a non-default port kept."""
    assert normalize_url("HTTPS://Example.COM:443/a#x") == "https://example.com/a"
    assert normalize_url("http://example.com:80") == "http://example.com/"
    assert normalize_url("https://example.com:8443/a") == "https://example.com:8443/a"


def test_normalize_url_keeps_the_brackets_of_an_ipv6_host() -> None:
    """An IPv6 literal goes back into the URL bracketed, with a non-default port."""
    assert normalize_url("http://[::1]:8000/a#x") == "http://[::1]:8000/a"
    assert normalize_url("HTTPS://[2001:DB8::7]:443") == "https://[2001:db8::7]/"


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------


def test_scope_host_only() -> None:
    """``Scope.HOST`` allows only the exact host."""
    target = Target.parse("https://example.com", scope=Scope.HOST)
    assert target.in_scope("https://example.com/x")
    assert not target.in_scope("https://api.example.com/x")
    assert not target.in_scope("https://evil.test/x")


def test_scope_subdomains() -> None:
    """``Scope.SUBDOMAINS`` allows the registrable domain and its subdomains, nothing else."""
    target = Target.parse("https://example.com", scope=Scope.SUBDOMAINS)
    assert target.in_scope("https://example.com/x")
    assert target.in_scope("https://api.example.com/x")
    assert not target.in_scope("https://example.com.evil.test/x")
    assert not target.in_scope("https://notexample.com/x")


def test_scope_subdomains_with_multi_label_suffix() -> None:
    """A bundled multi-label suffix (``co.uk``) is treated as a public suffix."""
    target = Target.parse("https://shop.example.co.uk", scope=Scope.SUBDOMAINS)
    assert target.in_scope("https://api.example.co.uk/x")
    assert not target.in_scope("https://example.org.uk/x")


def test_scope_of_a_one_label_or_ipv6_host_is_that_host_only() -> None:
    """With no registrable domain, ``Scope.SUBDOMAINS`` behaves like ``Scope.HOST``."""
    for raw in ("http://app:8000/", "http://[::1]:8000/"):
        target = Target.parse(raw, scope=Scope.SUBDOMAINS)
        assert target.in_scope(f"{target.origin}/x")
        assert not target.in_scope("http://other:8000/x")
        assert not target.in_scope("http://evil.app:8000/x")
        assert not target.in_scope("http://[::2]:8000/x")
