"""
Target parsing, URL normalization, and scope checks — RF-01, RF-02.
"""

from __future__ import annotations

import pytest

from webvigil.core import InvalidTargetError, Scope, Target, normalize_url

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


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def test_normalize_url_lowercases_and_drops_default_port_and_fragment() -> None:
    """Scheme and host lower-cased, default port and fragment dropped, a non-default port kept."""
    assert normalize_url("HTTPS://Example.COM:443/a#x") == "https://example.com/a"
    assert normalize_url("http://example.com:80") == "http://example.com/"
    assert normalize_url("https://example.com:8443/a") == "https://example.com:8443/a"


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
