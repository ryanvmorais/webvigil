"""
The Public Suffix List reader behind ``--scope subdomains``.

Two layers. The algorithm runs over a small list written here, so each rule kind (plain,
wildcard, exception, Unicode) is pinned without depending on what publicsuffix.org lists today.
Then a sample of the list's own test vectors (``tests/test_psl.txt`` upstream) runs over the
vendored copy, which also proves the file ships, parses and matches its ``PROVENANCE.json``.
No network: the vendored file is read through ``importlib.resources``.
"""

from __future__ import annotations

import hashlib
import json
from importlib.resources import files

import pytest

from webvigil.core.suffixes import load_rules, parse_rules

_LIST = """\
// ===BEGIN ICANN DOMAINS===
com
uk
co.uk
*.ck
!www.ck
公司.cn
cn
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io trailing words are ignored
// ===END PRIVATE DOMAINS===
"""


# ---------------------------------------------------------------------------
# The algorithm, over a list written here
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("example.com", "example.com"),
        ("www.example.com", "example.com"),
        ("com", None),
        ("shop.example.co.uk", "example.co.uk"),
        ("co.uk", None),
        ("alice.github.io", "alice.github.io"),
        ("www.alice.github.io", "alice.github.io"),
        ("github.io", None),
        ("test.ck", None),  # *.ck: any one label under ck is a suffix
        ("b.test.ck", "b.test.ck"),
        ("www.ck", "www.ck"),  # !www.ck: the exception is registrable
        ("www.www.ck", "www.ck"),
        ("xn--55qx5d.cn", None),  # 公司.cn, held in punycode
        ("shop.xn--55qx5d.cn", "shop.xn--55qx5d.cn"),
        ("example.unlisted", "example.unlisted"),  # no rule: the implicit "*"
        ("WWW.Example.COM.", "example.com"),
        ("a..example.com", None),
    ],
)
def test_the_registrable_domain_follows_the_list_rules(host: str, expected: str | None) -> None:
    """Plain, wildcard and exception rules, Unicode rules and the implicit ``*``."""
    assert parse_rules(_LIST).registrable_domain(host) == expected


def test_comments_and_blank_lines_are_not_rules() -> None:
    """``//`` lines and blank lines hold no rule; a line is read up to its first space."""
    rules = parse_rules(_LIST)
    assert "github.io" in rules.exact
    assert not any(rule.startswith("//") for rule in rules.exact)
    assert rules.wildcards == frozenset({"ck"})
    assert rules.exceptions == frozenset({"www.ck"})


# ---------------------------------------------------------------------------
# The vendored list
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("com", None),
        ("example.com", "example.com"),
        ("b.example.uk.com", "example.uk.com"),
        ("test.ac", "test.ac"),
        ("test.ac.jp", "test.ac.jp"),
        ("ide.kyoto.jp", None),
        ("a.b.ide.kyoto.jp", "b.ide.kyoto.jp"),
        ("c.kobe.jp", None),
        ("a.b.c.kobe.jp", "b.c.kobe.jp"),
        ("www.city.kobe.jp", "city.kobe.jp"),
        ("test.ck", None),
        ("www.www.ck", "www.ck"),
        ("www.test.k12.ak.us", "test.k12.ak.us"),
        ("xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn"),
        ("bob.github.io", "bob.github.io"),
        ("example.example", "example.example"),
    ],
)
def test_the_vendored_list_passes_the_upstream_test_vectors(
    host: str, expected: str | None
) -> None:
    """A sample of publicsuffix.org's own vectors, ICANN and PRIVATE sections both."""
    assert load_rules().registrable_domain(host) == expected


def test_the_vendored_list_is_the_file_its_provenance_describes() -> None:
    """The ``.dat`` keeps its MPL-2.0 header and hashes to the recorded SHA-256."""
    data = files("webvigil.core.data")
    raw = data.joinpath("public_suffix_list.dat").read_bytes()
    provenance = json.loads(data.joinpath("PROVENANCE.json").read_text(encoding="utf-8"))
    assert hashlib.sha256(raw).hexdigest() == provenance["sha256"]
    assert provenance["license"] == "MPL-2.0"
    text = raw.decode("utf-8")
    assert "Mozilla Public" in text.splitlines()[0] + text.splitlines()[1]
    assert "// ===BEGIN PRIVATE DOMAINS===" in text
