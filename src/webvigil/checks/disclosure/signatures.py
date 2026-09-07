"""
Compiled signatures for framework error pages and directory listings (RF-01, RF-02).

Pure data — no I/O. Each :class:`ErrorSignature` keys on the framework's
*chrome* (its debugger markup, its stack-trace layout), not on the words
"error" or "exception" alone, so a generic "something went wrong" page and a
blog post that quotes a traceback do not match (RNF-05).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from webvigil.core.findings import Severity

_SNIPPET_MAX = 400


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
            r"|<div id=\"summary\">\s*<h1>.+ at /"
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
            r"|<h1>\s*(?:ActionController|ActiveRecord|NoMethodError|RuntimeError)\b"
            r"|<code>.+app/controllers/.+\.rb</code>",
            re.S,
        ),
        interactive=False,
        severity=Severity.MEDIUM,
    ),
    ErrorSignature(
        "ASP.NET",
        re.compile(
            r"Server Error in .{1,40} Application"
            r"|<b>\s*Exception Details:\s*</b>"
            r"|\[[A-Za-z][\w.]*Exception:[^\]]*\]",
        ),
        interactive=False,
        severity=Severity.MEDIUM,
    ),
    ErrorSignature(
        "PHP",
        re.compile(
            r"<b>(?:Fatal error|Parse error|Uncaught \w+)</b>:.{1,400}?"
            r" in <b>.{1,300}?</b> on line <b>\d+</b>"
            r"|(?:PHP )?(?:Fatal error|Parse error):.{1,400}? in .{1,300}?\.php"
            r"(?:\(\d+\))? on line \d+",
            re.S,
        ),
        interactive=False,
        severity=Severity.MEDIUM,
    ),
    ErrorSignature(
        "PHP",
        re.compile(
            r"<b>(?:Warning|Notice|Deprecated)</b>:.{1,400}? in <b>.{1,300}?</b> on line <b>\d+</b>"
            r"|(?:PHP )?(?:Warning|Notice|Deprecated):.{1,400}? in .{1,300}?\.php on line \d+",
            re.S,
        ),
        interactive=False,
        severity=Severity.LOW,
    ),
    ErrorSignature(
        "Java",
        re.compile(
            r"(?:[a-z][\w.]*\.)+[A-Z]\w*(?:Exception|Error)(?::[^\n<]*)?"
            r"(?:\s|<br\s*/?>|\n)*(?:\s|&nbsp;)*at [\w.$/]+\([\w. ]+\.(?:java|jsp):\d+\)",
            re.S,
        ),
        interactive=False,
        severity=Severity.MEDIUM,
    ),
    ErrorSignature(
        "Node.js",
        re.compile(
            r"(?:Error|TypeError|ReferenceError|RangeError|SyntaxError):[^\n<]{1,200}"
            r"(?:\s|<br\s*/?>|\n)+(?:\s|&nbsp;)*at [^\n<]{1,200}"
            r"\([^\n<)]*(?::\d+){1,2}\)",
            re.S,
        ),
        interactive=False,
        severity=Severity.MEDIUM,
    ),
    ErrorSignature(
        "Python",
        re.compile(
            r"Traceback \(most recent call last\):" r"(?:\s|<br\s*/?>|\n)+(?:\s|&nbsp;)*File [\"&]",
            re.S,
        ),
        interactive=False,
        severity=Severity.MEDIUM,
    ),
)

LISTING_SIGNATURES: tuple[re.Pattern[str], ...] = (
    re.compile(r"<title>\s*Index of /"),
    re.compile(r"<title>\s*Directory listing for /"),
    re.compile(r"<h1>\s*Index of /"),
)


def match_error(body: str) -> ErrorMatch | None:
    """
    Args:
        body (str): A response body.

    Returns:
        ErrorMatch | None: The first (most-specific) framework error signature
            that fires, with its matched snippet, or ``None``.
    """
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
    return any(pattern.search(body) for pattern in LISTING_SIGNATURES)
