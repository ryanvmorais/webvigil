"""
The ``robots.txt`` rules follow RFC 9309, with the same decision on every supported Python.

The table pins exact decisions, from the RFC's own figures and examples and from rules real sites
write. Generated input comes from fixed seeds, and cost is measured by counting operations, never
with a clock. Sites are played by an in-process transport, so nothing leaves the machine.
"""

from __future__ import annotations

import asyncio
import random
from collections import deque
from collections.abc import Callable

import httpx2
import pytest

from tests.support import HandlerTransport
from webvigil.core.config import ScanConfig
from webvigil.core.errors import OutOfScopeError
from webvigil.core.target import Target
from webvigil.crawler import robots
from webvigil.crawler.crawler import Crawler
from webvigil.crawler.robots import Verdict
from webvigil.http.client import HttpClient

_ORIGIN = "https://example.com"
_UA = "WebVigil/0.1 (+https://example.com/bot)"

# The example of RFC 9309, 5.1.
_RFC_EXAMPLE = """\
User-Agent: *
Disallow: *.gif$
Disallow: /example/
Allow: /publications/

User-Agent: foobot
Disallow:/
Allow:/example/page.html
Allow:/example/allowed.gif

User-Agent: barbot
User-Agent: bazbot
Disallow: /example/page.html

User-Agent: quxbot
"""
_RFC_LONGEST = """\
User-Agent: foobot
Allow: /example/page/
Disallow: /example/page/disallowed.gif
"""
_MERGED = """\
user-agent: ExampleBot
disallow: /foo
disallow: /bar

user-agent: ExampleBot
disallow: /baz
"""
_NO_MATCH = """\
user-agent: *
disallow: /foo
disallow: /bar

user-agent: BazBot
disallow: /baz
"""
_WORDPRESS = """\
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /*?replytocom=
Disallow: /*.pdf$
Sitemap: https://example.com/sitemap.xml
"""


def _only(rule: str) -> str:
    """
    Args:
        rule (str): The value of a ``Disallow`` line.

    Returns:
        str: A file whose one group, for every agent, holds that rule.
    """
    return f"User-agent: *\nDisallow: {rule}\n"


# (case id, file, agent, path and query, allowed)
_DECISIONS: list[tuple[str, str, str, str, bool]] = [
    # RFC 9309, 5.1: the fallback group
    ("example-star-allow", _RFC_EXAMPLE, "otherbot", "/publications/a", True),
    ("example-star-prefix", _RFC_EXAMPLE, "otherbot", "/example/x", False),
    ("example-star-suffix", _RFC_EXAMPLE, "otherbot", "/images/a.gif", False),
    ("example-star-suffix-only", _RFC_EXAMPLE, "otherbot", "/a.gif?size=1", True),
    ("example-star-longer-allow", _RFC_EXAMPLE, "otherbot", "/publications/a.gif", True),
    # RFC 9309, 5.1: a group of its own, without the optional space
    ("example-foobot-page", _RFC_EXAMPLE, "foobot", "/example/page.html", True),
    ("example-foobot-gif", _RFC_EXAMPLE, "foobot", "/example/allowed.gif", True),
    ("example-foobot-other", _RFC_EXAMPLE, "foobot", "/other", False),
    ("example-foobot-root", _RFC_EXAMPLE, "foobot", "/", False),
    # RFC 9309, 5.1: one group for two agents
    ("example-barbot", _RFC_EXAMPLE, "barbot", "/example/page.html", False),
    ("example-bazbot", _RFC_EXAMPLE, "bazbot", "/example/page.html", False),
    ("example-bazbot-other", _RFC_EXAMPLE, "bazbot", "/other", True),
    # RFC 9309, 5.1: an empty group, which does not fall back to ``*``
    ("example-quxbot", _RFC_EXAMPLE, "quxbot", "/example/page.html", True),
    # RFC 9309, 5.2
    ("longest-disallow", _RFC_LONGEST, "foobot", "/example/page/disallowed.gif", False),
    ("longest-allow", _RFC_LONGEST, "foobot", "/example/page/other.gif", True),
    # RFC 9309, 2.2.1, figures 2 and 3
    ("merge-first", _MERGED, "examplebot", "/foo", False),
    ("merge-first-2", _MERGED, "examplebot", "/bar", False),
    ("merge-second", _MERGED, "examplebot", "/baz", False),
    ("merge-control", _MERGED, "examplebot", "/qux", True),
    (
        "merge-star",
        "User-agent: *\nDisallow: /a\n\nUser-agent: *\nDisallow: /b\n",
        _UA,
        "/b",
        False,
    ),
    ("fallback-star", _NO_MATCH, "examplebot", "/foo", False),
    ("fallback-not-other-group", _NO_MATCH, "examplebot", "/baz", True),
    ("named-group-replaces-star", _NO_MATCH, "BazBot", "/foo", True),
    ("no-group-no-rules", "User-agent: other\nDisallow: /\n", "webvigil", "/page", True),
    # RFC 9309, 2.2.2, figure 4: the encoded forms compare equal, in both directions
    (
        "query-rule-plain",
        _only("/foo/bar?baz=https://foo.bar"),
        _UA,
        "/foo/bar?baz=https%3A%2F%2Ffoo.bar",
        False,
    ),
    (
        "query-url-plain",
        _only("/foo/bar?baz=https%3A%2F%2Ffoo.bar"),
        _UA,
        "/foo/bar?baz=https://foo.bar",
        False,
    ),
    ("utf8-rule-plain", _only("/foo/bar/ツ"), _UA, "/foo/bar/%E3%83%84", False),
    ("utf8-url-plain", _only("/foo/bar/%E3%83%84"), _UA, "/foo/bar/ツ", False),
    ("unreserved-url-escaped", _only("/foo/bar/baz"), _UA, "/foo/bar/%62%61%7A", False),
    ("unreserved-rule-escaped", _only("/foo/bar/%62%61%7A"), _UA, "/foo/bar/baz", False),
    ("escape-hex-case", _only("/a%c3%a9"), _UA, "/a%C3%A9", False),
    ("unreserved-range-ends", _only("/AZaz09-._~"), _UA, "/%41%5A%61%7A%30%39%2D%2E%5F%7E", False),
    # RFC 9309, 2.2.3, figure 6: a special character matched verbatim
    ("escaped-star", _only("/path/file-with-a-%2A.html"), _UA, "/path/file-with-a-*.html", False),
    ("escaped-star-not-wild", _only("/path/file-%2A.html"), _UA, "/path/file-x.html", True),
    ("escaped-dollar", _only("/path/foo-%24"), _UA, "/path/foo-$", False),
    ("escaped-dollar-not-anchor", _only("/path/foo-%24"), _UA, "/path/foo-", True),
    # An encoded slash is data, never a path separator
    ("slash-url-escaped", _only("/a/b"), _UA, "/a%2Fb", True),
    ("slash-rule-escaped", _only("/a%2Fb"), _UA, "/a/b", True),
    ("slash-both-escaped", _only("/a%2Fb"), _UA, "/a%2fb", False),
    ("query-delimiter-stays", _only("/p?a=1"), _UA, "/p?a%3D1", True),
    ("path-question-mark-stays", _only("/a?b"), _UA, "/a%3Fb", True),
    # Most specific match; a tie favours Allow
    ("tie-allow-first", "User-agent: *\nAllow: /page\nDisallow: /page\n", _UA, "/page", True),
    ("tie-allow-last", "User-agent: *\nDisallow: /page\nAllow: /page\n", _UA, "/page", True),
    ("tie-written-apart", "User-agent: *\nAllow: /%62ar\nDisallow: /bar\n", _UA, "/bar", True),
    ("longer-disallow", "User-agent: *\nAllow: /a\nDisallow: /a/b\n", _UA, "/a/b", False),
    ("longer-allow", "User-agent: *\nDisallow: /a\nAllow: /a/b\n", _UA, "/a/b", True),
    ("order-does-not-decide", "User-agent: *\nDisallow: /a/b\nAllow: /a\n", _UA, "/a/b", False),
    ("wildcard-counts-octets", "User-agent: *\nAllow: /abc\nDisallow: /*bc\n", _UA, "/abc", True),
    (
        "escape-is-one-octet",
        "User-agent: *\nAllow: /abcdef\nDisallow: /*é\n",
        _UA,
        "/abcdefé",
        True,
    ),
    (
        "escape-counts-as-an-octet",
        "User-agent: *\nAllow: /%62a\nDisallow: /bar\n",
        _UA,
        "/bar",
        False,
    ),
    ("anchor-counts-an-octet", "User-agent: *\nAllow: /a\nDisallow: /a$\n", _UA, "/a", False),
    # Empty and malformed values
    ("empty-disallow", "User-agent: *\nDisallow:\n", _UA, "/page", True),
    ("empty-disallow-with-rule", "User-agent: *\nDisallow:\nDisallow: /x\n", _UA, "/x", False),
    ("empty-allow-grants-nothing", "User-agent: *\nAllow:\nDisallow: /x\n", _UA, "/x", False),
    ("value-not-a-path", "User-agent: *\nDisallow: private\n", _UA, "/private", True),
    ("line-without-colon", "User-agent: *\nDisallow /x\nDisallow: /y\n", _UA, "/x", True),
    ("after-a-bad-line", "User-agent: *\nDisallow /x\nDisallow: /y\n", _UA, "/y", False),
    ("unknown-record", "User-agent: *\nNoindex: /x\nDisallow: /y\n", _UA, "/x", True),
    ("bare-directive", "User-agent: a\nDisallow\nUser-agent: b\nDisallow: /x\n", "a", "/x", False),
    # Groups, lines and comments
    ("rule-before-any-group", "Disallow: /x\nUser-agent: *\nDisallow: /y\n", _UA, "/x", True),
    ("empty-line-in-a-group", "User-agent: *\nDisallow: /x\n\nDisallow: /y\n", _UA, "/y", False),
    (
        "empty-line-between-agents",
        "User-agent: a\n\nUser-agent: b\nDisallow: /x\n",
        "a",
        "/x",
        False,
    ),
    (
        "rule-closes-the-agents",
        "User-agent: a\nDisallow: /x\nUser-agent: b\nDisallow: /y\n",
        "a",
        "/y",
        True,
    ),
    (
        "crawl-delay-keeps-group",
        "User-agent: a\nCrawl-delay: 1\nUser-agent: b\nDisallow: /\n",
        "a",
        "/x",
        False,
    ),
    (
        "request-rate-keeps-group",
        "User-agent: a\nRequest-rate: 1/5\nUser-agent: b\nDisallow: /\n",
        "a",
        "/x",
        False,
    ),
    (
        "sitemap-keeps-group",
        "User-agent: a\nSitemap: /s.xml\nUser-agent: b\nDisallow: /\n",
        "a",
        "/x",
        False,
    ),
    ("inline-comment", "User-agent: * # all\nDisallow: /x # a note\n", _UA, "/x", False),
    ("comment-is-not-the-value", "User-agent: *\nDisallow: /x#y\n", _UA, "/xz", False),
    ("directive-case", "USER-AGENT: *\nDISALLOW: /x\n", _UA, "/x", False),
    ("space-before-colon", "User-agent : *\nDisallow : /x\n", _UA, "/x", False),
    ("crlf", "User-agent: *\r\nDisallow: /x\r\nDisallow: /y\r\n", _UA, "/y", False),
    ("cr", "User-agent: *\rDisallow: /x\rDisallow: /y\r", _UA, "/y", False),
    ("byte-order-mark", "\ufeffUser-agent: *\nDisallow: /x\n", _UA, "/x", False),
    (
        "other-breaks-are-not-lines",
        "User-agent: *\nDisallow: /a\u2028Disallow: /b\n",
        _UA,
        "/b",
        True,
    ),
    ("form-feed-is-not-a-line", "User-agent: *\nDisallow: /a\x0cDisallow: /b\n", _UA, "/b", True),
    # Which group an agent reads
    ("agent-any-case", "User-agent: WEBVIGIL\nDisallow: /x\n", _UA, "/x", False),
    ("agent-with-version", "User-agent: webvigil/1.0\nDisallow: /x\n", _UA, "/x", False),
    ("agent-is-not-a-substring", "User-agent: web\nDisallow: /x\n", _UA, "/x", True),
    ("agent-with-no-token", "User-agent: 123\nDisallow: /x\n", _UA, "/x", True),
    ("no-token-matches-no-token", "User-agent: 456\nDisallow: /x\n", "123bot", "/x", True),
    ("star-with-a-note", "User-agent: * everyone\nDisallow: /x\n", _UA, "/x", False),
    ("star-before-a-name", "User-agent: *bot\nDisallow: /x\n", _UA, "/x", True),
    ("path-is-case-sensitive", _only("/Private"), _UA, "/private", True),
    # Wildcards and the final ``$``
    ("star-matches-all", _only("*"), _UA, "/any/thing", False),
    ("star-matches-slash", _only("/a*z"), _UA, "/a/b/z", False),
    ("star-matches-nothing", _only("/a*z"), _UA, "/az", False),
    ("segments-in-order", _only("/*a*b*c"), _UA, "/xaybzc", False),
    ("segments-out-of-order", _only("/*a*b*c"), _UA, "/cba", True),
    ("segments-do-not-overlap", _only("/*ab*bc"), _UA, "/abc", True),
    ("repeated-star", _only("/a**b"), _UA, "/axb", False),
    ("trailing-star", _only("/fish*"), _UA, "/fish.html", False),
    ("wildcard-in-query", _only("/search?q=*&page=1"), _UA, "/search?q=a&page=1", False),
    ("anchor-tail-right-after", _only("/*ab*cd$"), _UA, "/abcd", False),
    ("anchor-exact", _only("/end$"), _UA, "/end", False),
    ("anchor-longer", _only("/end$"), _UA, "/end/more", True),
    ("anchor-after-star", _only("/*.php$"), _UA, "/a/b.php", False),
    ("anchor-after-star-longer", _only("/*.php$"), _UA, "/a/b.php?x=1", True),
    ("anchor-tail-after-position", _only("/*ab*b$"), _UA, "/ab", True),
    ("star-then-anchor", _only("/end*$"), _UA, "/endless", False),
    ("root-anchor", _only("/$"), _UA, "/", False),
    ("root-anchor-other", _only("/$"), _UA, "/page", True),
    ("double-dollar-literal", _only("/end$$"), _UA, "/end$", False),
    ("double-dollar-not-end", _only("/end$$"), _UA, "/end", True),
    ("dollar-then-star", _only("/end$*"), _UA, "/end$more", False),
    ("dollar-then-star-other", _only("/end$*"), _UA, "/end", True),
    ("inner-dollar-literal", _only("/a$b"), _UA, "/a$b", False),
    # What is compared
    ("robots-file-allowed", _only("/"), _UA, "/robots.txt", True),
    ("robots-file-with-query", _only("/"), _UA, "/robots.txt?x=1", False),
    ("robots-file-longer", _only("/"), _UA, "/robots.txtx", False),
    ("query-is-compared", _only("/search?q="), _UA, "/search?q=a", False),
    ("query-control", _only("/search?q="), _UA, "/search", True),
    ("fragment-is-not", _only("/a$"), _UA, "/a#part", False),
    ("empty-path-is-root", _only("/$"), _UA, "", False),
    ("non-ascii-matches", _only("/café"), _UA, "/caf%C3%A9/menu", False),
    ("invalid-escape-literal", _only("/100%"), _UA, "/100%25", False),
    ("invalid-escape-inside", _only("/100%off"), _UA, "/100%off", False),
    ("unpaired-surrogate-rule", _only("/mark\ud800er"), _UA, "/page", True),
    # Rules real sites write
    ("wordpress-admin", _WORDPRESS, _UA, "/wp-admin/options.php", False),
    ("wordpress-ajax", _WORDPRESS, _UA, "/wp-admin/admin-ajax.php", True),
    ("wordpress-reply", _WORDPRESS, _UA, "/post/1?replytocom=2", False),
    ("wordpress-post", _WORDPRESS, _UA, "/post/1", True),
    ("wordpress-pdf", _WORDPRESS, _UA, "/files/a.pdf", False),
    ("wordpress-pdf-query", _WORDPRESS, _UA, "/files/a.pdf?download=1", True),
]


@pytest.mark.parametrize(
    ("text", "agent", "path", "allowed"),
    [case[1:] for case in _DECISIONS],
    ids=[case[0] for case in _DECISIONS],
)
def test_the_decision_is_the_one_the_rfc_gives(
    text: str, agent: str, path: str, allowed: bool
) -> None:
    """The exact decision for this file, agent and URL."""
    assert robots._parse(text).can_fetch(agent, f"{_ORIGIN}{path}") is allowed


def test_the_sitemaps_are_read_from_anywhere_in_the_file() -> None:
    """Before, inside and after the groups, in order, with the empty value left out."""
    parsed = robots._parse(
        "Sitemap: https://example.com/a.xml\n"
        "User-agent: *\n"
        "sitemap: https://example.com/b.xml # a note\n"
        "Sitemap:\n"
        "Disallow: /x\n"
        "SITEMAP : https://example.com/c.xml\n"
    )

    assert parsed.sitemaps == (
        "https://example.com/a.xml",
        "https://example.com/b.xml",
        "https://example.com/c.xml",
    )
    assert parsed.can_fetch(_UA, f"{_ORIGIN}/x") is False


def test_no_robots_file_allows_everything() -> None:
    """The permissive stand-in decides without reading the URL."""
    assert robots.Robots.allow_all().verdict(_UA, "https://[unclosed/page") is Verdict.ALLOW


def test_a_url_that_cannot_be_read_is_disallowed_even_with_no_rule_for_it() -> None:
    """Not a limit, so the verdict is a plain refusal; a readable URL of the same file passes."""
    parsed = robots._parse("User-agent: other\nDisallow: /\n")

    assert parsed.verdict(_UA, "https://[unclosed/page") is Verdict.DISALLOW
    assert parsed.verdict(_UA, f"{_ORIGIN}/page") is Verdict.ALLOW


# ---------------------------------------------------------------------------
# No input raises
# ---------------------------------------------------------------------------

_LINE_PARTS = [
    "User-agent",
    "Allow",
    "Disallow",
    "Sitemap",
    "Crawl-delay",
    "Request-rate",
    ":",
    "#",
    "*",
    "$",
    "%",
    "%2",
    "%zz",
    "%2F",
    "%C3",
    "/",
    "?",
    "[",
    "]",
    " ",
    "\t",
    "\x00",
    "\x0b",
    "\x85",
    "\u2028",
    "\ud800",
    "\udfff",
    "é",
    "ツ",
    "\U0001f600",
    "9" * 5000,
    "a",
]
_URL_PARTS = ["https://", "example.com", "[", "]", "::1", "/", "?", "#", "%", "%2F", "\ud800", "é"]


def _random_text(rng: random.Random, parts: list[str], length: int) -> str:
    """
    Args:
        rng (random.Random): The seeded generator.
        parts (list[str]): What to draw from.
        length (int): How many parts to join.

    Returns:
        str: The parts, in random order, with an occasional line break.
    """
    return "".join(rng.choice([*parts, "\n", "\r\n", "\r"]) for _ in range(length))


@pytest.mark.parametrize("seed", range(40))
def test_no_file_and_no_url_raises(seed: int) -> None:
    """The decision is always one of the three, and ``can_fetch`` agrees with it."""
    rng = random.Random(seed)
    text = _random_text(rng, _LINE_PARTS, 400)
    parsed = robots._parse(text)
    urls = [_random_text(rng, _URL_PARTS, rng.randint(0, 12)) for _ in range(25)]
    agents = [_UA, "*", "", "\ud800", "a b", _random_text(rng, _LINE_PARTS, 3)]

    for agent in agents:
        for url in urls:
            verdict = parsed.verdict(agent, url)
            assert verdict in Verdict
            assert parsed.can_fetch(agent, url) is (verdict is Verdict.ALLOW)


# ---------------------------------------------------------------------------
# What one decision can cost
# ---------------------------------------------------------------------------


class _CountingText(str):
    """A string that records every search made on it, as ``(start, where it was found)``."""

    searches: list[tuple[int, int]]

    def __new__(cls, value: str) -> _CountingText:
        """
        Args:
            value (str): The text.

        Returns:
            _CountingText: It, with an empty record.
        """
        made = super().__new__(cls, value)
        made.searches = []
        return made

    def find(self, sub: str, *args: object) -> int:  # type: ignore[override]
        """
        Args:
            sub (str): What to look for.
            *args (object): The start of the search, and its end if it has one.

        Returns:
            int: The position ``str.find`` gives.
        """
        start = args[0] if args else 0
        assert isinstance(start, int)
        found = str.find(self, sub, *args)
        self.searches.append((start, found))
        return found


def _rule(value: str) -> robots._Rule:
    """
    Args:
        value (str): The value of a ``Disallow`` line.

    Returns:
        robots._Rule: It, compiled.
    """
    rule = robots._compile_rule(False, value)
    assert rule is not None
    return rule


def test_each_wildcard_segment_is_searched_once_and_the_position_only_moves_forward() -> None:
    """A repetitive URL that fails at the last segment still costs one search per segment."""
    target = _CountingText("/" + "ab" * 200)

    assert robots._matches(_rule("/*ab*ab*ab*zz"), target, len(target)) is False

    assert len(target.searches) == 4
    assert [start for start, _ in target.searches] == [1, 3, 5, 7]


def test_a_failed_segment_ends_the_search() -> None:
    """Nothing after a segment that is not there is looked for."""
    target = _CountingText("/" + "ab" * 200)

    assert robots._matches(_rule("/*zz*ab*ab"), target, len(target)) is False

    assert target.searches == [(1, -1)]


def test_the_anchored_tail_is_not_searched() -> None:
    """A final ``$`` compares the end of the URL in one step."""
    target = _CountingText("/" + "ab" * 200)

    assert robots._matches(_rule("/*ab*ab$"), target, len(target)) is True

    assert target.searches == [(1, 1)]


def test_a_segment_is_looked_for_once_in_the_path_and_once_in_the_query() -> None:
    """A URL with a query costs at most two searches per segment, over parts that do not overlap."""
    path = "/" + "ab" * 20
    target = _CountingText(f"{path}?x=cd")

    assert robots._matches(_rule("/*cd*zz"), target, len(path)) is False

    assert target.searches == [(1, -1), (len(path) + 1, len(path) + 3), (len(path) + 5, -1)]


def test_a_rule_is_compared_once_per_decision(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no match, one comparison per rule, and the most specific match stops the walk."""
    calls: list[robots._Rule] = []
    real = robots._matches

    def counted(rule: robots._Rule, target: str, path_end: int) -> bool:
        calls.append(rule)
        return real(rule, target, path_end)

    monkeypatch.setattr(robots, "_matches", counted)
    rules = "".join(f"Disallow: /*x{n}\n" for n in range(50))
    parsed = robots._parse(f"User-agent: *\n{rules}Disallow: /*page\n")

    assert parsed.verdict(_UA, f"{_ORIGIN}/other") is Verdict.ALLOW
    assert len(calls) == 51
    calls.clear()
    assert parsed.verdict(_UA, f"{_ORIGIN}/page") is Verdict.DISALLOW
    assert len(calls) == 1  # ``/*page`` is the longest rule, so it decides first


def _rule_lines(count: int) -> str:
    """
    Args:
        count (int): How many rules.

    Returns:
        str: That many ``Disallow`` lines, none matching ``/page``.
    """
    return "".join(f"Disallow: /r{n}/\n" for n in range(count))


# The ceilings are repeated here so a change to a constant fails a test.
_RULES_CEILING = 16_384
_PATTERN_CEILING = 2_048
_URL_CEILING = 8_192
_COST_CEILING = 8_000_000


def test_the_rule_ceiling_is_exact() -> None:
    """At the ceiling the rules decide; one more and nothing can be evaluated."""
    at = robots._parse(f"User-agent: *\n{_rule_lines(_RULES_CEILING)}")
    over = robots._parse(f"User-agent: *\n{_rule_lines(_RULES_CEILING + 1)}")

    assert at.verdict(_UA, f"{_ORIGIN}/page") is Verdict.ALLOW
    assert at.verdict(_UA, f"{_ORIGIN}/r7/") is Verdict.DISALLOW
    assert over.verdict(_UA, f"{_ORIGIN}/page") is Verdict.OVER_LIMIT
    assert over.can_fetch(_UA, f"{_ORIGIN}/page") is False
    assert over.verdict(_UA, f"{_ORIGIN}/robots.txt") is Verdict.ALLOW


def test_the_rule_ceiling_counts_the_joined_groups() -> None:
    """Two groups of one agent count together, and a group for another agent does not count."""
    half = _rule_lines(_RULES_CEILING // 2 + 1)
    joined = robots._parse(f"User-agent: webvigil\n{half}User-agent: webvigil\n{half}")
    apart = robots._parse(f"User-agent: webvigil\n{half}User-agent: other\n{half}")

    assert joined.verdict(_UA, f"{_ORIGIN}/page") is Verdict.OVER_LIMIT
    assert apart.verdict(_UA, f"{_ORIGIN}/page") is Verdict.ALLOW


@pytest.mark.parametrize("directive", ["Allow", "Disallow"])
def test_the_pattern_ceiling_is_exact(directive: str) -> None:
    """Measured on the canonical form: a rule that encoding grows past it counts as over it."""
    at = robots._parse(f"User-agent: *\n{directive}: /{'a' * (_PATTERN_CEILING - 1)}\n")
    over = robots._parse(f"User-agent: *\n{directive}: /{'a' * _PATTERN_CEILING}\n")
    grown = robots._parse(f"User-agent: *\n{directive}: /{'é' * (_PATTERN_CEILING // 6 + 1)}\n")
    # a value that is not a path is no rule at all, so it is not measured
    not_a_path = robots._parse(f"User-agent: *\n{directive}: {'a' * (_PATTERN_CEILING + 1)}\n")

    assert at.verdict(_UA, f"{_ORIGIN}/page") is Verdict.ALLOW
    assert over.verdict(_UA, f"{_ORIGIN}/page") is Verdict.OVER_LIMIT
    assert grown.verdict(_UA, f"{_ORIGIN}/page") is Verdict.OVER_LIMIT
    assert not_a_path.verdict(_UA, f"{_ORIGIN}/page") is Verdict.ALLOW


def test_the_url_ceiling_is_exact() -> None:
    """A URL past it is not read; with no rule for the agent there is nothing to evaluate."""
    parsed = robots._parse("User-agent: webvigil\nDisallow: /x\nUser-agent: other\nAllow: /\n")
    free = robots._parse("User-agent: other\nDisallow: /x\n")
    padding = _URL_CEILING - len(f"{_ORIGIN}/")
    at = f"{_ORIGIN}/{'a' * padding}"
    over = f"{at}a"

    assert len(at) == _URL_CEILING
    assert parsed.verdict(_UA, at) is Verdict.ALLOW
    assert parsed.verdict(_UA, over) is Verdict.OVER_LIMIT
    assert free.verdict(_UA, over) is Verdict.ALLOW


def test_a_file_over_a_ceiling_still_refuses_a_url_past_the_url_ceiling() -> None:
    """Both limits at once: the URL is reported as over the limit, not as allowed."""
    parsed = robots._parse(f"User-agent: *\n{_rule_lines(_RULES_CEILING + 1)}")

    assert parsed.verdict(_UA, f"{_ORIGIN}/{'a' * _URL_CEILING}") is Verdict.OVER_LIMIT


def test_the_search_cost_ceiling_stops_the_walk(monkeypatch: pytest.MonkeyPatch) -> None:
    """Counted in comparisons made: the rule that would pass the ceiling is never searched."""
    calls: list[robots._Rule] = []
    real = robots._matches

    def counted(rule: robots._Rule, target: str, path_end: int) -> bool:
        calls.append(rule)
        return real(rule, target, path_end)

    monkeypatch.setattr(robots, "_matches", counted)
    url_chars = 2_000
    search_chars = 1_000
    fitting = _COST_CEILING // (url_chars * search_chars)
    assert fitting * url_chars * search_chars == _COST_CEILING  # exactly at it, still allowed
    stem = "z" * (search_chars - 1)
    lines = "".join(f"Disallow: /*{stem}{chr(97 + n)}\n" for n in range(fitting))
    path = "/" + "a" * (url_chars - 1)
    at = robots._parse(f"User-agent: *\n{lines}")
    over = robots._parse(f"User-agent: *\n{lines}Disallow: /*{stem}y\n")

    assert at.verdict(_UA, f"{_ORIGIN}{path}") is Verdict.ALLOW
    assert len(calls) == fitting
    calls.clear()
    assert over.verdict(_UA, f"{_ORIGIN}{path}") is Verdict.OVER_LIMIT
    assert len(calls) == fitting


def test_a_rule_that_starts_otherwise_costs_no_search() -> None:
    """Only a rule whose text before its first ``*`` begins the URL is charged: no other matches."""
    url_chars = 2_000
    search_chars = 1_000
    rules = _COST_CEILING // (url_chars * search_chars) + 1  # charged, they would pass the ceiling
    stem = "z" * (search_chars - 1)
    lines = "".join(f"Disallow: /other*{stem}{chr(97 + n)}\n" for n in range(rules))
    parsed = robots._parse(f"User-agent: *\n{lines}")

    assert parsed.verdict(_UA, f"{_ORIGIN}/{'a' * (url_chars - 1)}") is Verdict.ALLOW
    assert parsed.verdict(_UA, f"{_ORIGIN}/other{'a' * (url_chars - 6)}") is Verdict.OVER_LIMIT


def test_a_literal_rule_costs_no_search() -> None:
    """Thousands of plain rules on a long URL stay within the ceiling, whatever their number."""
    parsed = robots._parse(f"User-agent: *\n{_rule_lines(_RULES_CEILING)}")

    assert parsed.verdict(_UA, f"{_ORIGIN}/page/{'a' * 8_000}") is Verdict.ALLOW


# ---------------------------------------------------------------------------
# The crawl over a ceiling
# ---------------------------------------------------------------------------


async def _crawl(robots_txt: str) -> tuple[Crawler, list[str]]:
    """
    Args:
        robots_txt (str): The body of ``/robots.txt``.

    Returns:
        tuple[Crawler, list[str]]: The finished crawl of a home page that links ``/a``, and the
            paths it asked for.
    """
    asked: list[str] = []

    def answer(request: httpx2.Request) -> httpx2.Response:
        asked.append(request.url.path)
        if request.url.path == "/robots.txt":
            return httpx2.Response(200, headers={"content-type": "text/plain"}, text=robots_txt)
        body = '<html><body><a href="/a">a</a></body></html>'
        return httpx2.Response(200, headers={"content-type": "text/html"}, text=body)

    target = Target.parse(f"{_ORIGIN}/")
    config = ScanConfig().with_overrides(http={"delay_ms": 0})
    async with HttpClient(target, config, transport=HandlerTransport(answer)) as http:
        crawler = Crawler(http, target, config)
        await crawler.discover()
    return crawler, asked


async def test_a_file_over_the_ceiling_keeps_the_crawl_out_and_the_scan_says_so() -> None:
    """The link is not fetched, it counts as skipped, and the limit warning names the file."""
    crawler, asked = await _crawl(f"User-agent: *\n{_rule_lines(_RULES_CEILING + 1)}")

    assert "/a" not in asked
    assert "/" in asked  # the path under test ran
    assert crawler.skipped_by_robots == 1
    assert crawler.limit_warning == (
        "the site declared more than the crawl keeps (robots.txt rules): the rest was left out"
    )


async def test_a_file_at_the_ceiling_is_followed_with_no_warning() -> None:
    """The control: the same crawl, one rule fewer."""
    crawler, asked = await _crawl(f"User-agent: *\n{_rule_lines(_RULES_CEILING)}")

    assert "/a" in asked
    assert crawler.skipped_by_robots == 0
    assert crawler.limit_warning is None


async def test_a_plain_refusal_is_not_reported_as_a_limit() -> None:
    """A rule that names the link skips it without saying the file was too large."""
    crawler, asked = await _crawl("User-agent: *\nDisallow: /a\n")

    assert "/a" not in asked
    assert crawler.skipped_by_robots == 1
    assert crawler.limit_warning is None


async def test_with_follow_robots_off_the_file_decides_nothing() -> None:
    """Even a file over the ceiling: the link is fetched and no limit is named."""
    asked: list[str] = []

    def answer(request: httpx2.Request) -> httpx2.Response:
        asked.append(request.url.path)
        if request.url.path == "/robots.txt":
            body = f"User-agent: *\n{_rule_lines(_RULES_CEILING + 1)}"
            return httpx2.Response(200, headers={"content-type": "text/plain"}, text=body)
        page = '<html><body><a href="/a">a</a></body></html>'
        return httpx2.Response(200, headers={"content-type": "text/html"}, text=page)

    target = Target.parse(f"{_ORIGIN}/")
    config = ScanConfig().with_overrides(scan={"follow_robots": False}, http={"delay_ms": 0})
    async with HttpClient(target, config, transport=HandlerTransport(answer)) as http:
        crawler = Crawler(http, target, config)
        await crawler.discover()

    assert "/a" in asked
    assert crawler.skipped_by_robots == 0
    assert crawler.limit_warning is None


@pytest.mark.parametrize(
    ("rule", "denied", "allowed"),
    [
        ("/*name=", "/p?name=1", "/p?other=1"),
        ("/*a=1&b=", "/p?a=1&b=2", "/p?a=1&c=2"),
        ("/*a/b", "/p?x=a/b", "/p?x=a/c"),
        ("/*a:b", "/p?x=a:b", "/p?x=a-b"),
        ("/*.php?id=", "/x.php?id=1", "/x.php?other=1"),
        ("/*a%2Fb", "/p?x=a/b", "/p?x=a/c"),
        ("/*a/b", "/p?x=a%2Fb", "/p?x=a%2Fc"),
        ("/*a%2fb", "/p?x=a%2Fb", "/p?x=a%2Fc"),
        ("/*a/b%2Fc", "/p?x=a/b/c", "/p?x=a/b/d"),
        ("/*a%2Fb$", "/p?x=a/b", "/p?x=a/b&y=1"),
        ("/*a/b$", "/p?x=a%2Fb", "/p?x=a%2Fb&y=1"),
        ("/*a%2Fb*c", "/p?x=a/b&y=c", "/p?x=a/b&y=d"),
    ],
)
def test_a_wildcard_rule_reaches_text_in_the_query(rule: str, denied: str, allowed: str) -> None:
    """Text after a ``*`` compares the same whether the URL has it in the path or the query."""
    parsed = robots._parse(f"User-agent: *\nDisallow: {rule}\n")

    assert parsed.verdict(_UA, f"{_ORIGIN}{denied}") is Verdict.DISALLOW
    assert parsed.verdict(_UA, f"{_ORIGIN}{allowed}") is Verdict.ALLOW


@pytest.mark.parametrize(
    ("rule", "path"),
    [("/*a%2Fb", "/x/a/b"), ("/*a/b", "/x/a%2Fb"), ("/*a%2Fb$", "/x/a/b"), ("/*a/b$", "/x/a%2Fb")],
)
def test_an_escaped_slash_stays_distinct_in_the_path(rule: str, path: str) -> None:
    """Only in a query are the two the same: in a path, ``%2F`` is not a separator."""
    parsed = robots._parse(f"User-agent: *\nDisallow: {rule}\n")

    assert parsed.verdict(_UA, f"{_ORIGIN}{path}") is Verdict.ALLOW


@pytest.mark.parametrize("path", ["/a", "/a?", "/a?x=1", "/ab"])
def test_a_rule_ending_in_a_wildcard_covers_a_url_that_ends_at_its_prefix(path: str) -> None:
    """The empty text after the final ``*`` is found at the very end of the path."""
    parsed = robots._parse("User-agent: *\nDisallow: /a*\n")

    assert parsed.verdict(_UA, f"{_ORIGIN}{path}") is Verdict.DISALLOW
    assert parsed.verdict(_UA, f"{_ORIGIN}/b") is Verdict.ALLOW


def test_repeated_wildcards_compare_and_cost_as_one() -> None:
    """Empty segments would be searched one by one, and no ceiling would charge them."""
    many = robots._compile_rule(False, "/a" + "*" * 1000 + "z")
    one = robots._compile_rule(False, "/a*z")

    assert many is not None and one is not None
    assert many.segments == one.segments == ("/a", "z")
    assert many.search_chars == one.search_chars == 1


async def test_a_queue_of_denied_urls_stops_at_the_scan_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A denied URL sends nothing, so without this check no request would notice the limit."""
    config = ScanConfig.model_validate({"scan": {"follow_robots": True}})
    target = Target.parse(f"{_ORIGIN}/")
    parsed = robots._parse("User-agent: *\nDisallow: /\n")
    queue = deque(f"{_ORIGIN}/p{n}" for n in range(5))
    answers = iter([False, False, True])
    transport = HandlerTransport(lambda _request: httpx2.Response(200))

    async with HttpClient(target, config, transport=transport) as http:
        crawler = Crawler(http, target, config)
        monkeypatch.setattr(http, "past_deadline", lambda: next(answers))
        await crawler._drain(queue, set(), [], parsed, 10)

    assert list(queue) == [f"{_ORIGIN}/p3", f"{_ORIGIN}/p4"]  # stopped after the third
    assert crawler._skipped_by_robots == 3


async def test_past_deadline_reads_and_records_the_scan_limit() -> None:
    """No limit is never past it; a spent limit is, and the scan's statistics say so."""
    target = Target.parse(f"{_ORIGIN}/")
    transport = HandlerTransport(lambda _request: httpx2.Response(200))
    async with HttpClient(target, ScanConfig(), transport=transport) as http:
        http._deadline = None
        assert http.past_deadline() is False
        assert http.stats.deadline_reached is False
        http._deadline = asyncio.get_running_loop().time() - 1
        assert http.past_deadline() is True
        assert http.stats.deadline_reached is True


# ---------------------------------------------------------------------------
# Reading the file (spec 027, RF-11 and RF-12)
# ---------------------------------------------------------------------------


@pytest.fixture
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """The client retries a 5xx GET and a refused connection; only the wait is zeroed."""
    from webvigil.http import client as client_mod

    monkeypatch.setattr(client_mod, "BACKOFF_BASE_S", 0.0)
    monkeypatch.setattr(client_mod, "BACKOFF_JITTER_S", 0.0)


async def _load(answer: Callable[[httpx2.Request], httpx2.Response]) -> robots.Robots:
    """
    Args:
        answer (Callable[[httpx2.Request], httpx2.Response]): Plays the site's ``robots.txt``.

    Returns:
        robots.Robots: What :func:`robots.load` read.
    """
    target = Target.parse(f"{_ORIGIN}/")
    config = ScanConfig().with_overrides(http={"delay_ms": 0})
    async with HttpClient(target, config, transport=HandlerTransport(answer)) as http:
        return await robots.load(http, _ORIGIN, _UA)


def _status(
    code: int, body: str = "User-agent: *\nDisallow: /\nSitemap: /s.xml\n"
) -> Callable[[httpx2.Request], httpx2.Response]:
    """
    Args:
        code (int): The status ``robots.txt`` answers.
        body (str): Its body. Defaults to a file that disallows everything and names a sitemap.

    Returns:
        Callable[[httpx2.Request], httpx2.Response]: The handler.
    """
    return lambda _request: httpx2.Response(code, headers={"content-type": "text/plain"}, text=body)


@pytest.mark.usefixtures("_no_backoff")
@pytest.mark.parametrize("code", [500, 503, 599])
async def test_a_server_error_disallows_every_url(code: int) -> None:
    """RFC 9309, 2.3.1.4: a ``5xx`` is an unreachable file, whatever its body says."""
    rules = await _load(_status(code, body=""))

    assert rules.unreadable == f"HTTP {code}"
    assert rules.verdict(_UA, f"{_ORIGIN}/page") is Verdict.DISALLOW
    assert not rules.can_fetch(_UA, f"{_ORIGIN}/")
    assert rules.sitemaps == ()


@pytest.mark.usefixtures("_no_backoff")
async def test_a_refused_connection_disallows_every_url() -> None:
    """A network error, after the client's retries, is an unreachable file too."""
    asked: list[str] = []

    def refuse(request: httpx2.Request) -> httpx2.Response:
        asked.append(request.url.path)
        raise httpx2.ConnectError("connection refused", request=request)

    rules = await _load(refuse)

    assert asked and set(asked) == {"/robots.txt"}  # the path under test ran
    assert rules.unreadable == "ConnectError"
    assert not rules.can_fetch(_UA, f"{_ORIGIN}/page")


@pytest.mark.parametrize("code", [404, 403, 499, 301, 600])
async def test_a_status_that_is_not_a_server_error_allows_every_url(code: int) -> None:
    """A ``4xx`` (the file is not there) and any other status are not the site's rules."""
    rules = await _load(_status(code))

    assert rules.unreadable is None
    assert rules.can_fetch(_UA, f"{_ORIGIN}/page")
    assert rules.sitemaps == ()


@pytest.mark.parametrize("body", ["", "  \n\t\n"], ids=["empty", "blank"])
async def test_an_empty_file_allows_every_url(body: str) -> None:
    """A ``200`` with nothing in it forbids nothing."""
    rules = await _load(_status(200, body=body))

    assert rules.unreadable is None
    assert rules.can_fetch(_UA, f"{_ORIGIN}/page")


async def test_a_file_with_no_rule_allows_every_url() -> None:
    """The positive control of the cases above: a readable file, nothing in it forbids the URL."""
    rules = await _load(_status(200, body="User-agent: *\n# nothing kept out\n"))

    assert rules.unreadable is None
    assert rules.can_fetch(_UA, f"{_ORIGIN}/page")


async def test_a_scope_refusal_of_the_file_stays_permissive() -> None:
    """The file is at the target's origin, so the guard cannot refuse it; if it did, allow all."""

    class _Refusing:
        """Stands in for the client, with ``robots.txt`` outside the target's scope."""

        async def get(self, url: str) -> object:
            """
            Raises:
                OutOfScopeError: Always, as the scope guard would.
            """
            raise OutOfScopeError(url)

    rules = await robots.load(_Refusing(), _ORIGIN, _UA)  # type: ignore[arg-type]

    assert rules.unreadable is None
    assert rules.can_fetch(_UA, f"{_ORIGIN}/page")


def test_an_unreadable_file_is_the_only_one_that_says_so() -> None:
    """The stand-ins: no file allows, a file that could not be read refuses, with its reason."""
    assert robots.Robots.allow_all().unreadable is None
    refused = robots.Robots.disallow_all("HTTP 502")
    assert refused.unreadable == "HTTP 502"
    assert refused.verdict(_UA, f"{_ORIGIN}{'/x' * 10_000}") is Verdict.DISALLOW


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        (f"{_ORIGIN}/a?", False),
        (f"{_ORIGIN}/a?x", False),
        (f"{_ORIGIN}/a", True),
        (f"{_ORIGIN}/a#?", True),  # the fragment is not sent: the path has no query
        (f"{_ORIGIN}/a#frag?x", True),
    ],
)
def test_a_rule_ending_in_a_question_mark_matches_an_empty_query(url: str, allowed: bool) -> None:
    """RFC 9309, 2.2.2: ``/a?`` is the path ``/a`` with a query, even an empty one (RF-12)."""
    rules = robots._parse("User-agent: *\nDisallow: /a?\n")

    assert rules.can_fetch(_UA, url) is allowed


@pytest.mark.parametrize(("url", "allowed"), [(f"{_ORIGIN}/a", False), (f"{_ORIGIN}/a?", True)])
def test_an_anchored_rule_does_not_cover_an_empty_query(url: str, allowed: bool) -> None:
    """``/a$`` ends at ``/a``: the ``?`` of an empty query is part of the URL compared with it."""
    rules = robots._parse("User-agent: *\nDisallow: /a$\n")

    assert rules.can_fetch(_UA, url) is allowed


_CAFE = "/caf" + chr(0xE9) + "/"


def _latin1_file(size: int) -> bytes:
    """
    Args:
        size (int): The least length of the file, in octets.

    Returns:
        bytes: A ``latin-1`` file whose only rule disallows a path with a non-ASCII letter,
            padded with comment lines after it.
    """
    head = f"User-agent: *\nDisallow: {_CAFE}\n".encode("latin-1")
    line = b"# " + b"x" * 97 + b"\n"
    return head + line * max(0, (size - len(head)) // len(line) + 1)


@pytest.mark.parametrize("size", [1_024, 600 * 1_024], ids=["small", "600-kib"])
async def test_a_file_over_the_limit_is_read_in_its_declared_charset(size: int) -> None:
    """The part within 500 KiB decodes as the whole of a small file does (RF-12)."""
    body = _latin1_file(size)
    assert (len(body) > robots.MAX_ROBOTS_BYTES) is (size > robots.MAX_ROBOTS_BYTES)
    rules = await _load(
        lambda _request: httpx2.Response(
            200, headers={"content-type": "text/plain; charset=iso-8859-1"}, content=body
        )
    )

    assert not rules.can_fetch(_UA, f"{_ORIGIN}{_CAFE}menu")
    assert rules.can_fetch(_UA, f"{_ORIGIN}/cafe/menu")  # the rule is not a blanket refusal
