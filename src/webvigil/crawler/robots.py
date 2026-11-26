"""
robots.txt handling for the crawler (RF-07).

``robots.txt`` gates crawler *discovery* only — checks are never robots-gated.
It is also where we look for ``Sitemap:`` directives.

The rules follow RFC 9309 through this module's own parser, so a decision does not depend on the
Python that runs the scan. The file and the URLs it is asked about both come from the scanned
site: nothing here raises on what they hold, and what one URL can cost is bounded by construction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit

from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.http.client import HttpClient, decode_text

# RFC 9309, 2.5: a crawler must parse at least the first 500 KiB of robots.txt, and may stop
# there. A longer file is cut at its last whole line; every queued URL is checked against the
# rules, so their number bounds the crawl's cost.
MAX_ROBOTS_BYTES = 500 * 1024
# What one decision may look at. The crawl decides synchronously, once per queued URL, so these
# keep it from holding up the scan. Each is far above what a real site writes; past one of them
# the URL is not fetched and the crawl says so, because a rule left unread could have forbidden it.
_MAX_RULES = 16_384
_MAX_PATTERN_CHARS = 2_048
_MAX_URL_CHARS = 8_192
# The ceiling on the characters a wildcard search may compare for one URL, charged before each
# search at its worst case (the URL's length times the length of what is searched for). It is
# arithmetic on the input, so the outcome is the same on every Python and machine.
_MAX_SEARCH_COST = 8_000_000

_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_UNRESERVED_CLASS = r"A-Za-z0-9._~\-"
_PRODUCT_TOKEN = re.compile(r"[A-Za-z_-]+")
_WILDCARD_AGENT = "*"
_REPEATED_WILDCARD = re.compile(r"\*{2,}")
_ESCAPED_SLASH = "%2F"
_ROBOTS_PATH = "/robots.txt"


def _escapes(kept: str) -> re.Pattern[str]:
    """
    Args:
        kept (str): The characters, besides the unreserved ones, that stay as they are.

    Returns:
        re.Pattern[str]: What :func:`_canonical` rewrites: a percent escape, or any other
            character that is not kept.
    """
    return re.compile(f"%[0-9A-Fa-f]{{2}}|[^{_UNRESERVED_CLASS}{kept}]")


# The delimiters of each part of a URL stay literal, so ``%2F`` never becomes a path separator.
# Every other reserved character compares in its escaped form (RFC 9309, 2.2.2 and 2.2.3), and
# in a rule ``*`` stays a wildcard.
_URL_PATH = _escapes("/")
_URL_QUERY = _escapes("=&")
_RULE_PATH = _escapes("/*")
_RULE_QUERY = _escapes("=&*")


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class Verdict(Enum):
    """
    What the rules decide about one URL.

    Attributes:
        ALLOW: The URL may be fetched.
        DISALLOW: A rule forbids it, or it is not a URL that can be read.
        OVER_LIMIT: It could not be evaluated within this module's ceilings, so it is not fetched.
    """

    ALLOW = "allow"
    DISALLOW = "disallow"
    OVER_LIMIT = "over_limit"


@dataclass(frozen=True, slots=True)
class _Rule:
    """
    One ``Allow`` or ``Disallow`` value, ready to compare.

    Attributes:
        allow (bool): ``True`` for an ``Allow`` line.
        segments (tuple[str, ...]): The canonical text between its ``*`` wildcards, in order.
        query_segments (tuple[str, ...]): The same, as compared inside a query.
        anchored (bool): ``True`` when a final ``$`` ties it to the end of the URL.
        specificity (int): How many octets it has, the measure of the most specific match.
        search_chars (int): The length of what a wildcard search looks for.
        has_query (bool): ``True`` when the rule writes a ``?``, so it says where the query is.
    """

    allow: bool
    segments: tuple[str, ...]
    query_segments: tuple[str, ...]
    anchored: bool
    specificity: int
    search_chars: int
    has_query: bool


@dataclass(frozen=True, slots=True)
class _RequestTarget:
    """
    A URL's path and query, in the two forms a rule can be compared with.

    Attributes:
        parts (str): Each part under its own rules, for a rule that writes a ``?``.
        flat (str): All of it under the rules of a path, for a rule that does not: the text
            after its ``*`` may land in the query, and must compare the same there. In the
            query, where a slash delimits nothing, ``%2F`` is written as ``/``.
        path_end (int): Where the path of ``flat`` ends.
    """

    parts: str
    flat: str
    path_end: int


@dataclass(slots=True)
class _Group:
    """
    One group of a ``robots.txt``.

    Attributes:
        agents (set[str]): The product tokens it names, in lower case, or ``*``.
        rules (list[tuple[bool, str]]): Its rules as written: ``(is Allow, value)``.
    """

    agents: set[str] = field(default_factory=set)
    rules: list[tuple[bool, str]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _AgentRules:
    """
    The rules that apply to one product token.

    Attributes:
        rules (tuple[_Rule, ...]): Most specific first, and ``Allow`` first on a tie.
        over_limit (bool): ``True`` when they exceed a ceiling and cannot be evaluated.
    """

    rules: tuple[_Rule, ...] = ()
    over_limit: bool = False


@dataclass(slots=True)
class _RuleSet:
    """
    The groups of a parsed file, and the rules already worked out for an agent.

    Attributes:
        groups (list[_Group]): The groups, in file order.
        by_agent (dict[str, _AgentRules]): The compiled rules of each product token asked about.
    """

    groups: list[_Group]
    by_agent: dict[str, _AgentRules] = field(default_factory=dict)

    def for_agent(self, token: str) -> _AgentRules:
        """
        Args:
            token (str): A product token in lower case.

        Returns:
            _AgentRules: The joined rules of every group naming ``token``, or of the ``*``
                groups when none does, compiled once.
        """
        if token not in self.by_agent:
            chosen = [group for group in self.groups if token in group.agents] or [
                group for group in self.groups if _WILDCARD_AGENT in group.agents
            ]
            self.by_agent[token] = _compile_rules(chosen)
        return self.by_agent[token]


@dataclass(frozen=True, slots=True)
class Robots:
    """
    A parsed robots.txt, a permissive stand-in when there is none, or a refusal when it could
    not be read.

    Attributes:
        sitemaps (tuple[str, ...]): ``Sitemap:`` URLs declared in the file.
        unreadable (str | None): Why the file could not be read (``"HTTP 503"``, the kind of a
            network failure), when it could not: every URL is then disallowed (RFC 9309, 2.3.1.4).
    """

    _rules: _RuleSet | None
    sitemaps: tuple[str, ...]
    unreadable: str | None = None

    def verdict(self, user_agent: str, url: str) -> Verdict:
        """
        Decide one URL under RFC 9309. Never raises, whatever the file or the URL holds.

        Args:
            user_agent (str): The crawler's ``User-Agent`` string; its leading product token
                selects the group.
            url (str): The absolute URL the crawler wants to fetch.

        Returns:
            Verdict: The decision. :attr:`Verdict.ALLOW` when there is no ``robots.txt``, and
                :attr:`Verdict.DISALLOW` for every URL when it could not be read.
        """
        if self.unreadable is not None:
            return Verdict.DISALLOW
        if self._rules is None:
            return Verdict.ALLOW
        applied = self._rules.for_agent(_product_token(user_agent))
        if len(url) > _MAX_URL_CHARS:
            return Verdict.OVER_LIMIT if applied.rules or applied.over_limit else Verdict.ALLOW
        target = _request_target(url)
        if target is None:
            return Verdict.DISALLOW  # a URL from a HAR or an OpenAPI document may not parse
        if target.parts == _ROBOTS_PATH:
            return Verdict.ALLOW  # RFC 9309, 2.2.2: always implicitly allowed
        if applied.over_limit:
            return Verdict.OVER_LIMIT
        return _evaluate(applied.rules, target)

    def can_fetch(self, user_agent: str, url: str) -> bool:
        """
        Args:
            user_agent (str): The crawler's ``User-Agent`` string.
            url (str): The absolute URL the crawler wants to fetch.

        Returns:
            bool: ``True`` when the rules allow it, or always when there is no
                ``robots.txt``. ``False`` when ``url`` cannot be evaluated against the rules,
                and always when the file could not be read.
        """
        return self.verdict(user_agent, url) is Verdict.ALLOW

    @classmethod
    def allow_all(cls) -> Robots:
        """
        Returns:
            Robots: A permissive instance with no rules and no sitemaps.
        """
        return cls(_rules=None, sitemaps=())

    @classmethod
    def disallow_all(cls, reason: str) -> Robots:
        """
        Args:
            reason (str): Why the file could not be read, in words written by this project.

        Returns:
            Robots: An instance that disallows every URL, with no sitemaps.
        """
        return cls(_rules=None, sitemaps=(), unreadable=reason)


# ---------------------------------------------------------------------------
# Comparing a rule with a URL
# ---------------------------------------------------------------------------


def _rewrite(match: re.Match[str]) -> str:
    """
    Args:
        match (re.Match[str]): A percent escape or a single character to encode.

    Returns:
        str: An escape of an unreserved character decoded, any other escape in upper case, or
            the character's UTF-8 octets as escapes. An unpaired surrogate is encoded as written,
            so no text can make this raise.
    """
    token = match[0]
    if len(token) == 3:
        octet = int(token[1:], 16)
        char = chr(octet)
        return char if char in _UNRESERVED else f"%{octet:02X}"
    return "".join(f"%{octet:02X}" for octet in token.encode("utf-8", "surrogatepass"))


def _canonical(text: str, path: re.Pattern[str], query: re.Pattern[str]) -> str:
    """
    Args:
        text (str): A path with an optional query, from a rule or a URL.
        path (re.Pattern[str]): What to rewrite before the first ``?``.
        query (re.Pattern[str]): What to rewrite after it.

    Returns:
        str: The form two equivalent values share (RFC 9309, 2.2.2).
    """
    head, mark, tail = text.partition("?")
    return path.sub(_rewrite, head) + mark + query.sub(_rewrite, tail)


def _request_target(url: str) -> _RequestTarget | None:
    """
    Args:
        url (str): An absolute URL.

    Returns:
        _RequestTarget | None: Its path and query in canonical form (at least ``/``, and never
            the fragment, which is not sent), or ``None`` when it cannot be parsed. A ``?`` with
            an empty query is kept, so ``/a?`` is not ``/a`` and a rule ``/a?`` matches it.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    path = parts.path or "/"
    has_query = "?" in url.partition("#")[0]  # ``urlsplit`` drops the ``?`` of an empty query
    target = f"{path}?{parts.query}" if has_query else path
    head = _URL_PATH.sub(_rewrite, path)
    flat = head
    if has_query:
        flat = f"{head}?{_URL_PATH.sub(_rewrite, parts.query).replace(_ESCAPED_SLASH, '/')}"
    return _RequestTarget(
        parts=_canonical(target, _URL_PATH, _URL_QUERY), flat=flat, path_end=len(head)
    )


def _segment_end(rule: _Rule, index: int, text: str, position: int, path_end: int) -> int:
    """
    Args:
        rule (_Rule): The rule.
        index (int): Which of its segments to look for.
        text (str): A canonical path and query.
        position (int): Where the search starts.
        path_end (int): Where the path of ``text`` ends.

    Returns:
        int: The end of the leftmost place for the segment, in the path first and then in the
            query, each in its own form; ``-1`` when it is in neither.
    """
    if position <= path_end:
        segment = rule.segments[index]
        found = text.find(segment, position, path_end)
        if found >= 0:
            return found + len(segment)
    if path_end >= len(text):
        return -1  # no query to look in
    segment = rule.query_segments[index]
    found = text.find(segment, max(position, path_end + 1))
    return found + len(segment) if found >= 0 else -1


def _matches(rule: _Rule, text: str, path_end: int) -> bool:
    """
    Match without backtracking: each segment is looked for once, after the one before it.

    The leftmost place for a segment leaves the most room for the next, so no earlier choice
    ever has to be reconsidered and the position only moves forward.

    Args:
        rule (_Rule): The rule.
        text (str): A canonical path and query.
        path_end (int): Where the path of ``text`` ends; its length for a form with no query
            of its own.

    Returns:
        bool: Whether the rule covers ``text``.
    """
    segments = rule.segments
    if not text.startswith(segments[0]):
        return False
    position = len(segments[0])
    last = len(segments) - 1
    if last == 0:
        return not rule.anchored or position == len(text)
    for index in range(1, last):
        position = _segment_end(rule, index, text, position, path_end)
        if position < 0:
            return False
    if rule.anchored:
        # A URL with a query ends inside it, and a rule compared here has no ``?`` to span it.
        final = segments[last] if path_end == len(text) else rule.query_segments[last]
        return len(text) - len(final) >= position and text.endswith(final)
    return _segment_end(rule, last, text, position, path_end) >= 0


def _evaluate(rules: tuple[_Rule, ...], target: _RequestTarget) -> Verdict:
    """
    Args:
        rules (tuple[_Rule, ...]): The agent's rules, most specific first.
        target (_RequestTarget): The URL's canonical path and query.

    Returns:
        Verdict: The first rule that matches decides (RFC 9309, 2.2.2). No match allows.
            :attr:`Verdict.OVER_LIMIT` once the searches would pass :data:`_MAX_SEARCH_COST`.
    """
    spent = 0
    for rule in rules:
        text = target.parts if rule.has_query else target.flat
        if not text.startswith(rule.segments[0]):
            continue
        spent += rule.search_chars * len(text)
        if spent > _MAX_SEARCH_COST:
            return Verdict.OVER_LIMIT
        if _matches(rule, text, len(text) if rule.has_query else target.path_end):
            return Verdict.ALLOW if rule.allow else Verdict.DISALLOW
    return Verdict.ALLOW


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _compile_rule(allow: bool, value: str) -> _Rule | None:
    """
    Args:
        allow (bool): ``True`` for an ``Allow`` line.
        value (str): The value as written, without its comment.

    Returns:
        _Rule | None: The rule, or ``None`` for an empty value (which forbids nothing) and for
            one that is not a path pattern, which cannot match any URL.
    """
    if not value.startswith(("/", "*")):
        return None
    anchored = value.endswith("$")
    canonical = _canonical(value[:-1] if anchored else value, _RULE_PATH, _RULE_QUERY)
    # ``**`` means ``*``, and each empty segment would be a search no ceiling charges
    segments = tuple(_REPEATED_WILDCARD.sub("*", canonical).split("*"))
    return _Rule(
        allow=allow,
        segments=segments,
        query_segments=tuple(part.replace(_ESCAPED_SLASH, "/") for part in segments),
        anchored=anchored,
        # An escape is one octet of the value, whichever way it was written.
        specificity=len(canonical) - 2 * canonical.count("%") + anchored,
        search_chars=sum(map(len, segments[1:])),
        has_query="?" in canonical,
    )


def _compile_rules(groups: list[_Group]) -> _AgentRules:
    """
    Args:
        groups (list[_Group]): The groups that apply to one agent.

    Returns:
        _AgentRules: Their rules joined and in order of precedence, or ``over_limit`` when
            they pass :data:`_MAX_RULES` or one passes :data:`_MAX_PATTERN_CHARS`.
    """
    if sum(len(group.rules) for group in groups) > _MAX_RULES:
        return _AgentRules(over_limit=True)
    rules: list[_Rule] = []
    for group in groups:
        for allow, value in group.rules:
            rule = _compile_rule(allow, value)
            if rule is None:
                continue
            if sum(map(len, rule.segments)) > _MAX_PATTERN_CHARS:
                return _AgentRules(over_limit=True)
            rules.append(rule)
    rules.sort(key=lambda rule: (-rule.specificity, not rule.allow))
    return _AgentRules(rules=tuple(rules))


def _product_token(value: str) -> str:
    """
    Args:
        value (str): A ``User-Agent`` header or the value of a ``User-agent`` line.

    Returns:
        str: Its leading run of letters, ``_`` and ``-``, in lower case; empty when it has none.
    """
    match = _PRODUCT_TOKEN.match(value)
    return match[0].lower() if match else ""


def _parse(text: str) -> Robots:
    """
    Read a ``robots.txt`` line by line. A line that cannot be read is skipped, never fatal.

    Consecutive ``User-agent`` lines open one group, and empty lines do not close it. Records
    other than ``User-agent``, ``Allow`` and ``Disallow`` (``Sitemap``, ``Crawl-delay``,
    ``Request-rate`` and the unknown ones) leave the groups as they are (RFC 9309, 2.2.4), and a
    rule before the first group is ignored.

    Args:
        text (str): The content of a ``robots.txt``.

    Returns:
        Robots: Its rules and sitemaps.
    """
    groups: list[_Group] = []
    sitemaps: list[str] = []
    group: _Group | None = None
    in_rules = False
    # RFC 9309, 2.2: only CR, LF and CRLF end a line, unlike ``str.splitlines``.
    for line in text.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        name, colon, rest = line.partition("#")[0].partition(":")
        if not colon:
            continue
        directive = name.strip().lower()
        value = rest.strip()
        if directive == "user-agent":
            if group is None or in_rules:
                group, in_rules = _Group(), False
                groups.append(group)
            words = value.split(maxsplit=1)
            agent = _WILDCARD_AGENT if words[:1] == [_WILDCARD_AGENT] else _product_token(value)
            if agent:
                group.agents.add(agent)
        elif directive in ("allow", "disallow"):
            if group is not None:
                in_rules = True
                group.rules.append((directive == "allow", value))
        elif directive == "sitemap" and value:
            sitemaps.append(value)
    return Robots(_rules=_RuleSet(groups), sitemaps=tuple(sitemaps))


async def load(http: HttpClient, origin: str, user_agent: str) -> Robots:
    """
    Fetch and parse ``<origin>/robots.txt``.

    RFC 9309, 2.3.1: a file that is not there (``4xx``) allows every URL, and one that cannot be
    reached (``5xx`` after the client's retries, or a network error) disallows every URL.

    Args:
        http (HttpClient): The shared HTTP client.
        origin (str): The target origin (scheme + host + port).
        user_agent (str): The crawler's ``User-Agent`` string (unused here, kept
            for symmetry with :meth:`Robots.can_fetch`).

    Returns:
        Robots: The parsed rules; :meth:`Robots.disallow_all` on a ``5xx`` or a network
            error; :meth:`Robots.allow_all` when the file is missing, empty or answers any
            other status.
    """
    try:
        response = await http.get(f"{origin}/robots.txt")
    except OutOfScopeError:  # the file is at the target's origin, so this cannot happen
        return Robots.allow_all()
    except RequestFailed as exc:
        return Robots.disallow_all(exc.reason)
    if 500 <= response.status_code <= 599:
        return Robots.disallow_all(f"HTTP {response.status_code}")
    if response.status_code != 200 or not response.text.strip():
        return Robots.allow_all()

    text = response.text
    if len(response.content) > MAX_ROBOTS_BYTES:
        # The part within the limit, cut at its last whole line and read in the same charset as
        # a smaller file is.
        head = response.content[:MAX_ROBOTS_BYTES].rpartition(b"\n")[0]
        text = decode_text(head, response.headers.get("content-type"))
    return _parse(text)
