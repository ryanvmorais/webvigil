"""
Redact secrets out of a probe response body before it enters a ``Finding`` (RNF-06, ADR-9).

The raw secret must never reach the ``ScanResult`` — which is persisted by the
Web API and rendered in four report formats. Redaction runs once, at the source,
inside :class:`~webvigil.checks.disclosure.probe.DisclosureProbe`.
"""

from __future__ import annotations

import json
import re
from typing import Any

_MASK = "***redacted***"
_VALUE_MASK = "***"
_LIMIT = 1024
_JSON_LIMIT = 2000
_MAX_LINES = 80
# Characters of a body the line strategies split into lines: what their ``_MAX_LINES`` lines can
# hold, without a list of every line of a long body.
_LINES_READ_MAX = 64 * 1024
# Characters of a JSON body parsed for the ``json-env`` strategy. The parsed document takes many
# times the memory of its text; a longer body gets the generic masking of its first ``_LIMIT``.
_JSON_PARSE_MAX = 256 * 1024

# Well-known secret shapes plus a catch-all for long high-entropy tokens. The text comes from the
# scanned site, so every repetition is bounded, and the pattern only ever reads a capped amount
# of it (``_LIMIT`` of a body, ``_JSON_LIMIT`` of the strings of a JSON body).
_SECRET_RE = re.compile(
    r"(?i)(?:"
    r"AKIA[0-9A-Z]{16}"
    r"|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,200}"
    r"|eyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,2048}"
    r"|-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----[\s\S]{0,8192}?-----END [A-Z ]{0,40}PRIVATE KEY-----"
    r"|[A-Za-z0-9+/]{40,4096}={0,2}"
    r"|[0-9a-f]{40,4096}"
    r")"
)
_KV_RE = re.compile(r"^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*[:=]\s*)(\S.*)$")

# The user name of an ``.htpasswd`` line, before the hash.
_HTPASSWD_RE = re.compile(r"^([^:\s]{1,256}):")

# The user information of a URL (``https://user:token@host``), whatever it holds.
_USERINFO_RE = re.compile(r"(?<=://)[^/\s@]{1,256}@")

# A name followed by an assignment, as a config file, a source file or a connection string
# writes one: ``name=``, ``name:``, ``"name":``, ``name =>`` and PHP's ``define('name',``. Only
# a secret-sounding name (:func:`_is_secret_name`) gets its value masked.
_ASSIGNMENT_RE = re.compile(
    r"(?<![\w.-])([A-Za-z_][\w.-]{0,127})"
    r"(?:[\"']?[ \t]{0,8}(?:=>|[:=])|[\"'][ \t]{0,8},)[ \t]{0,8}"
)
# The value after an assignment: quoted (up to its closing quote) or bare.
_VALUE_RE = re.compile(r"\"[^\"\n]{0,512}\"?|'[^'\n]{0,512}'?|[^\s\"'<>&;,]{1,512}")

# Names whose value is a secret: an exact name, a word anywhere in the name, or an ending. The
# name is lower-cased with everything but letters and digits removed (``DB_PASSWORD`` is
# ``dbpassword``), so every spelling of one word counts.
_SECRET_NAMES = frozenset({"value", "key", "pw", "pass", "auth"})
_SECRET_WORDS = (
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "apikey",
    "accesskey",
    "privatekey",
    "signingkey",
    "credential",
    "connectionstring",
    "authorization",
    "jwt",
)
_SECRET_ENDINGS = ("key", "pw", "pass", "auth")

#: The strategies a catalogue entry may name. An entry that names none gets ``generic``.
STRATEGIES: frozenset[str] = frozenset({"dotenv", "json-env", "generic", "htpasswd"})


def apply(strategy: str, body: str) -> str:
    """
    Return ``body`` with secrets removed according to ``strategy``, length-bounded.

    Args:
        strategy (str): One of ``"dotenv"`` (mask every ``KEY=value``), ``"json-env"`` (mask
            secret-named JSON keys), ``"htpasswd"`` (mask every hash after a user name) or
            ``"generic"`` (mask well-known token shapes, URL user information and the value
            of a secret-named assignment); any other name gets ``"generic"``.
        body (str): The raw response body.

    Returns:
        str: The redacted, length-bounded body.
    """
    if strategy == "dotenv":
        return _dotenv(body)
    if strategy == "json-env":
        return _json_env(body)
    if strategy == "htpasswd":
        return _htpasswd(body)
    return _generic(body[:_LIMIT])


def _generic(text: str) -> str:
    """
    Args:
        text (str): Already bounded text.

    Returns:
        str: ``text`` with URL user information, the value of every secret-named assignment
            and every well-known token shape masked.
    """
    text = _USERINFO_RE.sub(f"{_VALUE_MASK}@", text)
    return _SECRET_RE.sub(_MASK, _mask_assignments(text))


def _mask_assignments(text: str) -> str:
    """
    Args:
        text (str): Already bounded text.

    Returns:
        str: ``text`` with the value of every assignment to a secret-sounding name replaced by
            ``***``. The search goes on right after each assignment, so a secret assigned
            inside another value (a query string in a URL) is found too.
    """
    pieces: list[str] = []
    last = 0
    for match in _ASSIGNMENT_RE.finditer(text):
        if match.start() < last or not _is_secret_name(match.group(1)):
            continue
        value = _VALUE_RE.match(text, match.end())
        if value is None:
            continue
        pieces += [text[last : match.end()], _VALUE_MASK]
        last = value.end()
    pieces.append(text[last:])
    return "".join(pieces)


def _is_secret_name(name: str) -> bool:
    """
    Args:
        name (str): A key or variable name.

    Returns:
        bool: Whether its value is likely a secret (:data:`_SECRET_NAMES`,
            :data:`_SECRET_WORDS`, :data:`_SECRET_ENDINGS`).
    """
    plain = "".join(char for char in name.lower() if char.isascii() and char.isalnum())
    return (
        plain in _SECRET_NAMES
        or any(word in plain for word in _SECRET_WORDS)
        or plain.endswith(_SECRET_ENDINGS)
    )


def _dotenv(body: str) -> str:
    """
    Args:
        body (str): A dotenv-style body.

    Returns:
        str: The body with every value after a ``KEY=`` / ``KEY:`` replaced by a mask, the
            lines of a quoted value that spans lines dropped with it, and every other line
            given the generic masking; capped at ``_MAX_LINES`` lines and ``_LIMIT`` chars.
    """
    lines: list[str] = []
    open_quote = ""
    kept = 0
    for line in _head_lines(body):
        if open_quote:  # inside a value that spans lines: dropped up to its closing quote
            if open_quote in line:
                open_quote = ""
            continue
        match = _KV_RE.match(line)
        if match is None:
            lines.append(_generic(line[:_LIMIT]))
        else:
            lines.append(f"{match.group(1)}{_VALUE_MASK}")
            value = match.group(2)
            if value[0] in "\"'" and value[0] not in value[1:]:
                open_quote = value[0]
        kept += len(lines[-1]) + 1
        if kept > _LIMIT:  # the output is full: no later line is worth masking
            break
    return "\n".join(lines)[:_LIMIT]


def _htpasswd(body: str) -> str:
    """
    Args:
        body (str): An ``.htpasswd``-style body (``user:hash`` lines).

    Returns:
        str: The body with every hash after a user name replaced by a mask, every other line
            given the generic masking; capped at ``_MAX_LINES`` lines and ``_LIMIT`` chars.
    """
    lines: list[str] = []
    kept = 0
    for line in _head_lines(body):
        match = _HTPASSWD_RE.match(line)
        lines.append(f"{match.group(1)}:{_VALUE_MASK}" if match else _generic(line[:_LIMIT]))
        kept += len(lines[-1]) + 1
        if kept > _LIMIT:  # the output is full: no later line is worth masking
            break
    return "\n".join(lines)[:_LIMIT]


def _head_lines(body: str) -> list[str]:
    """
    Args:
        body (str): A line-oriented body.

    Returns:
        list[str]: Its first ``_MAX_LINES`` lines, read from its first ``_LINES_READ_MAX``
            characters, so a long body is not split whole.
    """
    return body[:_LINES_READ_MAX].splitlines()[:_MAX_LINES]


def _json_env(body: str) -> str:
    """
    Args:
        body (str): A JSON body (e.g. a config or env dump).

    Returns:
        str: The re-serialised JSON with secret-named keys masked and token
            shapes scrubbed from string values, up to ``_JSON_LIMIT`` characters;
            falls back to generic masking when the body is longer than
            ``_JSON_PARSE_MAX``, is not valid JSON or is nested too deep to walk.
    """
    if len(body) > _JSON_PARSE_MAX:
        return _generic(body[:_LIMIT])
    try:
        data = json.loads(body)
        # _scrub and the encoder recurse too: a body just inside the parser's depth limit can
        # still exhaust the stack here.
        return _serialised_head(_scrub(data, [_JSON_LIMIT]))
    except (ValueError, RecursionError):
        return _generic(body[:_LIMIT])


def _serialised_head(data: Any) -> str:
    """
    Serialise ``data`` as indented JSON, only as far as the kept part reaches.

    The indentation of a deeply nested document grows with every level, so its whole text can be
    hundreds of times the body it came from; the encoder yields it in pieces, and the pieces stop
    once ``_JSON_LIMIT`` characters are there.

    Args:
        data (Any): A JSON value.

    Returns:
        str: The first ``_JSON_LIMIT`` characters of its indented serialisation.
    """
    pieces: list[str] = []
    length = 0
    for piece in json.JSONEncoder(indent=2).iterencode(data):
        pieces.append(piece)
        length += len(piece)
        if length >= _JSON_LIMIT:
            break
    return "".join(pieces)[:_JSON_LIMIT]


def _scrub(node: Any, budget: list[int]) -> Any:
    """
    Recursively mask secret-named keys and token-shaped string values.

    Only the first ``_JSON_LIMIT`` characters of the serialised result are kept, so only that
    many characters of strings are worth scanning. Strings are visited in the order they are
    serialised; once ``budget`` is spent, every later string is masked without being scanned,
    and so is a string longer than the whole budget.

    Args:
        node (Any): Any JSON value.
        budget (list[int]): Characters of string left to scan, updated in place.

    Returns:
        Any: The same structure with secrets removed.
    """
    if isinstance(node, dict):
        return {
            key: (_VALUE_MASK if _is_secret_name(key) else _scrub(value, budget))
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [_scrub(item, budget) for item in node]
    if isinstance(node, str):
        if len(node) > budget[0]:
            budget[0] = 0
            return _VALUE_MASK
        budget[0] -= len(node)
        return _generic(node)
    return node
