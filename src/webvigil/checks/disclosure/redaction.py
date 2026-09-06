"""Redact secrets out of a probe response body before it enters a ``Finding`` (RNF-06, ADR-9).

The raw secret must never reach the ``ScanResult`` — which is persisted by the Web API and
rendered in four report formats. Redaction runs once, at the source, inside
``DisclosureProbe``.
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

# Well-known secret shapes plus a catch-all for long high-entropy tokens.
_SECRET_RE = re.compile(
    r"(?i)(?:"
    r"AKIA[0-9A-Z]{16}"
    r"|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
    r"|[A-Za-z0-9+/]{40,}={0,2}"
    r"|[0-9a-f]{40,}"
    r")"
)
_KV_RE = re.compile(r"^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*[:=]\s*)(\S.*)$")
_SECRET_KEYS = {"value", "password", "passwd", "secret", "token", "apikey", "api_key", "key"}


def apply(strategy: str, body: str) -> str:
    """Return ``body`` with secrets removed according to ``strategy``, length-bounded."""
    if strategy == "dotenv":
        return _dotenv(body)
    if strategy == "json-env":
        return _json_env(body)
    if strategy == "generic":
        return _SECRET_RE.sub(_MASK, body[:_LIMIT])
    return body[:_LIMIT]


def _dotenv(body: str) -> str:
    lines: list[str] = []
    for line in body.splitlines()[:_MAX_LINES]:
        match = _KV_RE.match(line)
        lines.append(f"{match.group(1)}{_VALUE_MASK}" if match else line)
    return "\n".join(lines)[:_LIMIT]


def _json_env(body: str) -> str:
    try:
        data = json.loads(body)
    except ValueError:
        return _SECRET_RE.sub(_MASK, body[:_LIMIT])
    return json.dumps(_scrub(data), indent=2)[:_JSON_LIMIT]


def _scrub(node: Any) -> Any:
    if isinstance(node, dict):
        return {
            key: (_VALUE_MASK if key.lower() in _SECRET_KEYS else _scrub(value))
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [_scrub(item) for item in node]
    if isinstance(node, str):
        return _SECRET_RE.sub(_MASK, node)
    return node
