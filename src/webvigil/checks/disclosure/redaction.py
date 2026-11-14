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
_SECRET_KEYS = {"value", "password", "passwd", "secret", "token", "apikey", "api_key", "key"}


def apply(strategy: str, body: str) -> str:
    """
    Return ``body`` with secrets removed according to ``strategy``, length-bounded.

    Args:
        strategy (str): One of ``"dotenv"`` (mask every ``KEY=value``),
            ``"json-env"`` (mask secret-named JSON keys), ``"generic"`` (mask
            well-known token shapes), or anything else (truncate only).
        body (str): The raw response body.

    Returns:
        str: The redacted, length-bounded body.
    """
    if strategy == "dotenv":
        return _dotenv(body)
    if strategy == "json-env":
        return _json_env(body)
    if strategy == "generic":
        return _SECRET_RE.sub(_MASK, body[:_LIMIT])
    return body[:_LIMIT]


def _dotenv(body: str) -> str:
    """
    Args:
        body (str): A dotenv-style body.

    Returns:
        str: The body with every value after a ``KEY=`` / ``KEY:`` replaced by a
            mask, capped at ``_MAX_LINES`` lines and ``_LIMIT`` chars.
    """
    lines: list[str] = []
    for line in body.splitlines()[:_MAX_LINES]:
        match = _KV_RE.match(line)
        lines.append(f"{match.group(1)}{_VALUE_MASK}" if match else line)
    return "\n".join(lines)[:_LIMIT]


def _json_env(body: str) -> str:
    """
    Args:
        body (str): A JSON body (e.g. a config or env dump).

    Returns:
        str: The re-serialised JSON with secret-named keys masked and token
            shapes scrubbed from string values; falls back to generic masking
            when the body is not valid JSON or is nested too deep to walk.
    """
    try:
        data = json.loads(body)
        # _scrub and json.dumps recurse too: a body just inside the parser's depth limit can
        # still exhaust the stack here.
        return json.dumps(_scrub(data, [_JSON_LIMIT]), indent=2)[:_JSON_LIMIT]
    except (ValueError, RecursionError):
        return _SECRET_RE.sub(_MASK, body[:_LIMIT])


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
            key: (_VALUE_MASK if key.lower() in _SECRET_KEYS else _scrub(value, budget))
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [_scrub(item, budget) for item in node]
    if isinstance(node, str):
        if len(node) > budget[0]:
            budget[0] = 0
            return _VALUE_MASK
        budget[0] -= len(node)
        return _SECRET_RE.sub(_MASK, node)
    return node
