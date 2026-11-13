"""
The Public Suffix List, read from the vendored copy: where a registrable domain begins.

``--scope subdomains`` widens the scope from the target host to its registrable domain and every
name under it. Where that domain begins is not "the last two labels": ``example.co.uk`` has
three, and on a shared host (``github.io``, ``herokuapp.com``, ``s3.amazonaws.com``) each tenant
is a registrable domain of its own, so ``alice.github.io`` must not bring ``bob.github.io`` into
scope. The list, with both its sections (the ICANN suffixes and the PRIVATE ones that shared
hosts register), lives in ``core/data/public_suffix_list.dat`` and is refreshed by
``scripts/update-public-suffix-list.py``; the engine never downloads it.

The algorithm is the list's own (https://publicsuffix.org/list/): an exception rule
(``!www.ck``) beats every other rule, otherwise the matching rule with the most labels wins, a
wildcard (``*.ck``) stands for exactly one label, and with no match the rule is ``*`` (the last
label is the suffix). A rule written in Unicode is held in its ASCII (punycode) form, the one a
target host is written in.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files

_PACKAGE = "webvigil.core.data"
_LIST_NAME = "public_suffix_list.dat"


# ---------------------------------------------------------------------------
# The rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SuffixRules:
    """
    The rules of a Public Suffix List, split by kind, every one in ASCII and lower case.

    Attributes:
        exact (frozenset[str]): Plain rules (``co.uk``, ``github.io``).
        wildcards (frozenset[str]): What follows ``*.`` in a wildcard rule (``ck`` for ``*.ck``).
        exceptions (frozenset[str]): What follows ``!`` in an exception rule (``www.ck``).
    """

    exact: frozenset[str]
    wildcards: frozenset[str]
    exceptions: frozenset[str]

    def _suffix_length(self, labels: list[str]) -> int:
        """
        Args:
            labels (list[str]): The host's labels, left to right.

        Returns:
            int: How many labels, counted from the right, form the public suffix.
        """
        count = len(labels)
        longest = 1  # the implicit "*" rule
        for start in range(count):
            candidate = ".".join(labels[start:])
            if candidate in self.exceptions:
                return count - start - 1  # an exception prevails; its leftmost label is not suffix
            wildcard = start + 1 < count and ".".join(labels[start + 1 :]) in self.wildcards
            if candidate in self.exact or wildcard:
                longest = max(longest, count - start)
        return longest

    def registrable_domain(self, host: str) -> str | None:
        """
        Args:
            host (str): A DNS name in ASCII (an IDN in its ``xn--`` form), e.g.
                ``"api.example.co.uk"``.

        Returns:
            str | None: The public suffix plus one label (``"example.co.uk"``), or ``None`` when
                ``host`` is itself a public suffix (``"co.uk"``, ``"github.io"``) or is not a
                well-formed name.
        """
        labels = host.lower().rstrip(".").split(".")
        if not all(labels):
            return None
        suffix = self._suffix_length(labels)
        if suffix >= len(labels):
            return None
        return ".".join(labels[-suffix - 1 :])


def _ascii(rule: str) -> str | None:
    """
    Args:
        rule (str): A rule's name part, possibly in Unicode (``公司.cn``).

    Returns:
        str | None: Its ASCII form (``xn--55qx5d.cn``), or ``None`` when IDNA cannot encode it;
            such a rule could not match a host written in ASCII anyway.
    """
    if rule.isascii():
        return rule.lower()
    try:
        return rule.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None


def parse_rules(text: str) -> SuffixRules:
    """
    Read a list in the publicsuffix.org format.

    Each line is read up to its first whitespace; ``//`` starts a comment line.

    Args:
        text (str): The list's text.

    Returns:
        SuffixRules: Its rules.
    """
    exact: set[str] = set()
    wildcards: set[str] = set()
    exceptions: set[str] = set()
    for line in text.splitlines():
        words = line.split(maxsplit=1)
        if not words or words[0].startswith("//"):
            continue
        rule = words[0]
        if rule.startswith("!"):
            bucket, name = exceptions, rule[1:]
        elif rule.startswith("*."):
            bucket, name = wildcards, rule[2:]
        else:
            bucket, name = exact, rule
        if (encoded := _ascii(name)) is not None:
            bucket.add(encoded)
    return SuffixRules(frozenset(exact), frozenset(wildcards), frozenset(exceptions))


@lru_cache(maxsize=1)
def load_rules() -> SuffixRules:
    """
    Returns:
        SuffixRules: The vendored list's rules. Parsed once per process.
    """
    text = files(_PACKAGE).joinpath(_LIST_NAME).read_text(encoding="utf-8")
    return parse_rules(text)


__all__ = ["SuffixRules", "load_rules", "parse_rules"]
