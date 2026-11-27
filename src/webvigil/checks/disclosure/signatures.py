"""
Compiled signatures for framework error pages and directory listings (RF-01, RF-02).

Pure data — no I/O. Each :class:`ErrorSignature` keys on the framework's
*chrome* (its debugger markup, its stack-trace layout), not on the words
"error" or "exception" alone, so a generic "something went wrong" page and a
blog post that quotes a traceback do not match (RNF-05).

The text these patterns read comes from the scanned site, so each one is written to cost
time proportional to the size of the body: every repetition is bounded, no two neighbouring
repetitions can match the same characters, a pattern that starts on a word starts on a word
boundary, and a message stops at the next heading of its own signature, so each character is read
from one place a match could start, however many headings a body repeats. The sweep in
``tests/unit/test_hostile_body_cost.py`` times every signature of both tables on bodies built from
its own pieces. :func:`match_error` also reads only the first ``_SCAN_MAX`` characters of a body.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from webvigil.core.findings import Severity

_SNIPPET_MAX = 400
# Characters of a body the signatures read. An error page carries its framework chrome near the
# top; a body that long past it is a document, not a debugger page, and the patterns would only
# spend time on it. The HTTP layer already caps a body at 10 MiB.
_SCAN_MAX = 256 * 1024


@dataclass(frozen=True, slots=True)
class ErrorSignature:
    """
    One recognisable framework error / stack-trace page.

    Attributes:
        framework (str): Framework name, shown in the finding and used as its
            dedup key.
        pattern (re.Pattern[str]): The compiled chrome pattern.
        interactive (bool): ``True`` for a live debugger console — a
            code-execution surface, reported at HIGH confidence.
        severity (Severity): Severity for a finding from this signature.
    """

    framework: str
    pattern: re.Pattern[str]
    interactive: bool
    severity: Severity


@dataclass(frozen=True, slots=True)
class ErrorMatch:
    """
    A signature that fired against a response body, plus the text that matched.

    Attributes:
        signature (ErrorSignature): The signature that fired.
        snippet (str): The matched text, whitespace-collapsed and capped at
            ``_SNIPPET_MAX``.
    """

    signature: ErrorSignature
    snippet: str


# Ordered most-specific first; ``match_error`` returns the first hit.
ERROR_SIGNATURES: tuple[ErrorSignature, ...] = (
    ErrorSignature(
        "Werkzeug",
        re.compile(r"Werkzeug Debugger|The Werkzeug debugger|werkzeug\.debug"),
        interactive=True,
        severity=Severity.HIGH,
    ),
    ErrorSignature(
        "Django",
        re.compile(
            r"You(?:&#39;|&#x27;|')re seeing this error because you have"
            r"|<div id=\"summary\">\s{0,200}<h1>[^<\n]{1,200} at /"
            r"|<th>Django Version:</th>",
            re.S,
        ),
        interactive=False,
        severity=Severity.MEDIUM,
    ),
    ErrorSignature(
        "Ruby on Rails",
        re.compile(
            r"Action Controller: Exception caught"
            r"|<h1>\s{0,200}(?:ActionController|ActiveRecord|NoMethodError|RuntimeError)\b"
            r"|<code>[^<\n]{1,300}app/controllers/[^<\n]{1,300}\.rb</code>",
            re.S,
        ),
        interactive=False,
        severity=Severity.MEDIUM,
    ),
    ErrorSignature(
        "ASP.NET",
        re.compile(
            r"Server Error in .{1,40} Application"
            r"|<b>\s{0,200}Exception Details:\s{0,200}</b>"
            # The bracketed message stops at the next "[", so it is read from one bracket only.
            r"|\[[A-Za-z][\w.]{0,300}Exception:[^\[\]\n]{0,500}\]",
        ),
        interactive=False,
        severity=Severity.MEDIUM,
    ),
    ErrorSignature(
        "PHP",
        re.compile(
            # The message stops at the next "<b>" (HTML) or the next heading (plain): each
            # character is read from one heading only, however many headings a body repeats. A
            # real message holding another heading still matches, from that heading. The file
            # path ends at the "<" of "</b>" (HTML), or before a newline or another " in "
            # (plain), so it is not read again from every " in " of the message.
            r"<b>(?:Fatal error|Parse error|Uncaught \w+)</b>:(?:(?!<b>).){1,400}?"
            r" in <b>[^<]{1,300}</b> on line <b>\d+</b>"
            r"|(?:PHP )?(?:Fatal error|Parse error):(?:(?!Fatal error:|Parse error:).){1,400}?"
            r" in (?:(?! in )[^\n<]){1,300}?\.php(?:\(\d+\))? on line \d+",
            re.S,
        ),
        interactive=False,
        severity=Severity.MEDIUM,
    ),
    ErrorSignature(
        "PHP",
        re.compile(
            # Bounded as the signature above.
            r"<b>(?:Warning|Notice|Deprecated)</b>:(?:(?!<b>).){1,400}?"
            r" in <b>[^<]{1,300}</b> on line <b>\d+</b>"
            r"|(?:PHP )?(?:Warning|Notice|Deprecated):"
            r"(?:(?!Warning:|Notice:|Deprecated:).){1,400}?"
            r" in (?:(?! in )[^\n<]){1,300}?\.php on line \d+",
            re.S,
        ),
        interactive=False,
        severity=Severity.LOW,
    ),
    ErrorSignature(
        "Java",
        re.compile(
            # A name starts only where no dotted name runs into it, so each dotted name is read
            # from its first segment only. The message stops at the next "Exception:" or
            # "Error:" (a nested exception matches from its own name) and ends on a character
            # the gap cannot start with, so each run of whitespace before "at" is read once.
            r"(?<![\w.])[a-z]\w{0,100}(?:\.\w{1,100}){0,12}\.[A-Z]\w{0,100}(?:Exception|Error)"
            r"(?::(?:(?:(?!Exception:|Error:)[^\n<]){0,499}[^\s<;])?)?"
            r"(?:\s|<br\s*/?>|&nbsp;){0,200}"
            r"at [\w.$/]{1,300}\([\w. ]{1,100}\.(?:java|jsp):\d+\)",
            re.S,
        ),
        interactive=False,
        severity=Severity.MEDIUM,
    ),
    ErrorSignature(
        "Node.js",
        re.compile(
            # As in the Java signature, the message stops at the next "Error:" and cannot end on
            # whitespace, and the function name stops at the first "(", so only one "(" of the
            # frame opens its location.
            r"(?:Error|TypeError|ReferenceError|RangeError|SyntaxError):"
            r"(?:(?:(?!Error:)[^\n<]){0,199}[^\s<;])?"
            r"(?:\s|<br\s*/?>|&nbsp;){1,200}at [^\n<(]{1,200}"
            r"\([^\n<)]{0,300}:\d+(?::\d+)?\)",
            re.S,
        ),
        interactive=False,
        severity=Severity.MEDIUM,
    ),
    ErrorSignature(
        "Python",
        re.compile(
            r"Traceback \(most recent call last\):" r"(?:\s|<br\s*/?>|&nbsp;){1,200}File [\"&]",
            re.S,
        ),
        interactive=False,
        severity=Severity.MEDIUM,
    ),
)

LISTING_SIGNATURES: tuple[re.Pattern[str], ...] = (
    re.compile(r"<title>\s{0,200}Index of /"),
    re.compile(r"<title>\s{0,200}Directory listing for /"),
    re.compile(r"<h1>\s{0,200}Index of /"),
)


def match_error(body: str) -> ErrorMatch | None:
    """
    Args:
        body (str): A response body.

    Returns:
        ErrorMatch | None: The first (most-specific) framework error signature
            that fires, with its matched snippet, or ``None``.
    """
    body = body[:_SCAN_MAX]
    for signature in ERROR_SIGNATURES:
        hit = signature.pattern.search(body)
        if hit is not None:
            text = " ".join(hit.group(0).split())
            if len(text) > _SNIPPET_MAX:
                text = text[:_SNIPPET_MAX] + " …"
            return ErrorMatch(signature, text)
    return None


def is_directory_listing(body: str) -> bool:
    """
    Args:
        body (str): A response body.

    Returns:
        bool: ``True`` when ``body`` is a server-generated directory index
            (Apache / nginx / ``http.server``).
    """
    body = body[:_SCAN_MAX]
    return any(pattern.search(body) for pattern in LISTING_SIGNATURES)
