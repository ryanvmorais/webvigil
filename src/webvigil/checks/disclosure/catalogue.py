"""
Load and expand the curated probe catalogue from ``data/paths.toml`` (RF-05, ADR-4).

Uses :mod:`importlib.resources` so it works from a wheel or an editable
checkout, never a path relative to this source file.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.resources import files
from typing import Any

from webvigil.core.errors import ConfigError
from webvigil.core.findings import Confidence, Severity

_PACKAGE = "webvigil.checks.disclosure.data"
_FILE = "paths.toml"

PROBE_CHECK_IDS = frozenset(
    {
        "disclosure.vcs.exposed",
        "disclosure.config.dotenv-exposed",
        "disclosure.config.manifest-exposed",
        "disclosure.backup.file-exposed",
        "disclosure.debug.endpoint-exposed",
        "disclosure.sourcemap.exposed",
    }
)

_SEVERITY = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
_CONFIDENCE = {"low": Confidence.LOW, "medium": Confidence.MEDIUM, "high": Confidence.HIGH}
_DEFAULT_OK_STATUS = frozenset({200, 206})

_DEFAULT_DESCRIPTION = {
    "vcs": (
        "Version-control metadata is reachable over HTTP, letting an attacker recover the "
        "application's source code and full commit history."
    ),
    "config": (
        "A server or framework configuration file is reachable over HTTP. These files "
        "routinely contain credentials, secret keys, and internal hostnames."
    ),
    "manifest": (
        "A dependency manifest is reachable over HTTP. It enumerates the exact packages and "
        "versions in use, which speeds up targeted attacks."
    ),
    "backup": (
        "A backup, archive, or database dump is reachable over HTTP. Such files frequently "
        "contain source code, credentials, or customer data."
    ),
    "debug": (
        "A debug or administrative endpoint is reachable over HTTP. It exposes configuration, "
        "environment, and internal state, and sometimes allows code execution."
    ),
    "sourcemap": (
        "A JavaScript source map is reachable over HTTP, exposing the original (pre-minified) "
        "source and its directory layout."
    ),
}

_BACKUP_ARCHIVE_MAGIC = {
    ".zip": (b"PK\x03\x04", b"PK\x05\x06"),
    ".tar.gz": (b"\x1f\x8b",),
    ".tgz": (b"\x1f\x8b",),
    ".sql.gz": (b"\x1f\x8b",),
}
_BACKUP_SQL_RE = re.compile(
    r"(?i)(CREATE TABLE|INSERT INTO|DROP TABLE IF EXISTS|-- MySQL dump|"
    r"PostgreSQL database dump|-- Dumping data)"
)
_BACKUP_SOURCE_RE = re.compile(
    r"(?i)(<\?php|<%@|DB_PASSWORD|SECRET_KEY|AWS_SECRET|password\s*[:=]|"
    r"BEGIN (?:RSA|OPENSSH|EC|DSA|PRIVATE)|connectionstring)"
)
_HIGH_BACKUP_SUFFIXES = frozenset({".sql", ".sql.gz"})


@dataclass(frozen=True, slots=True)
class Validator:
    """
    How a probe response body is confirmed to be what its path implies (RF-06).

    A response passes if **any** configured check passes.

    Attributes:
        content (re.Pattern[str] | None): Pattern the body must match at least
            ``min_matches`` times.
        min_matches (int): Required number of ``content`` matches. Defaults to 1.
        content_type (tuple[str, ...]): Substrings, any of which in the
            ``Content-Type`` passes.
        json_keys (tuple[str, ...]): Top-level JSON keys, any of which present
            passes.
        magic (tuple[bytes, ...]): Byte prefixes, any of which at the start of
            the raw body passes.
    """

    content: re.Pattern[str] | None = None
    min_matches: int = 1
    content_type: tuple[str, ...] = ()
    json_keys: tuple[str, ...] = ()
    magic: tuple[bytes, ...] = ()

    def passes(self, *, body: str, raw: bytes, content_type: str) -> bool:
        """
        Args:
            body (str): The decoded response body.
            raw (bytes): The raw response body.
            content_type (str): The response ``Content-Type``.

        Returns:
            bool: ``True`` when any configured check passes.
        """
        if self.magic and raw.startswith(self.magic):
            return True
        if self.content_type:
            ct = content_type.lower()
            if any(token in ct for token in self.content_type):
                return True
        if self.json_keys:
            try:
                data = json.loads(body)
            except ValueError:
                data = None
            if isinstance(data, dict) and any(key in data for key in self.json_keys):
                return True
        return self.content is not None and len(self.content.findall(body)) >= self.min_matches


@dataclass(frozen=True, slots=True)
class ProbeEntry:
    """
    One catalogue path to probe, resolved against the target origin at scan time.

    Attributes:
        path (str): Path relative to the origin.
        family (str): Probe family (``vcs``, ``config``, ``manifest``,
            ``backup``, ``debug``, ``sourcemap``).
        check_id (str): The probe-fed check this entry feeds.
        severity (Severity): Severity for a hit.
        confidence (Confidence): Confidence for a hit.
        title (str): Finding title.
        description (str): Finding description.
        validator (Validator): How a response is confirmed to be the real file.
        redaction (str): Redaction strategy for the body. Defaults to
            ``"none"``.
        ok_status (frozenset[int]): Status codes that count as a reachable
            resource. Defaults to ``{200, 206}``.
    """

    path: str
    family: str
    check_id: str
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    validator: Validator
    redaction: str = "none"
    ok_status: frozenset[int] = field(default_factory=lambda: _DEFAULT_OK_STATUS)


@lru_cache(maxsize=1)
def load_catalogue() -> tuple[ProbeEntry, ...]:
    """
    Parse ``paths.toml`` and expand the backup cross-product into a flat tuple of entries.

    Returns:
        tuple[ProbeEntry, ...]: Every catalogue entry, cached for the process.

    Raises:
        ConfigError: If the shipped file is not valid TOML, contains a bad
            regex, is empty, or names an unknown check.
    """
    text = files(_PACKAGE).joinpath(_FILE).read_text(encoding="utf-8")
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:  # pragma: no cover - shipped file
        raise ConfigError(f"invalid disclosure catalogue: {exc}") from exc

    entries = [_entry_from_toml(item) for item in raw.get("entry", ())]
    entries.extend(_expand_backups(raw.get("backups", {})))
    _validate(entries)
    return tuple(entries)


def _entry_from_toml(item: dict[str, Any]) -> ProbeEntry:
    """
    Args:
        item (dict[str, Any]): One ``[[entry]]`` table from ``paths.toml``.

    Returns:
        ProbeEntry: The parsed entry, with a family default description when
            none is given.
    """
    family = str(item["family"])
    return ProbeEntry(
        path=str(item["path"]),
        family=family,
        check_id=str(item["check"]),
        severity=_SEVERITY[str(item["severity"])],
        confidence=_CONFIDENCE[str(item.get("confidence", "high"))],
        title=str(item["title"]),
        description=str(item.get("description") or _DEFAULT_DESCRIPTION[family]),
        validator=_validator_from_toml(item),
        redaction=str(item.get("redact", "none")),
        ok_status=frozenset(int(code) for code in item.get("ok_status", _DEFAULT_OK_STATUS)),
    )


def _validator_from_toml(item: dict[str, Any]) -> Validator:
    """
    Args:
        item (dict[str, Any]): One entry table, for its validator keys.

    Returns:
        Validator: The compiled validator.

    Raises:
        ConfigError: If the entry's ``content`` regex will not compile.
    """
    content = item.get("content")
    try:
        pattern = re.compile(str(content)) if content else None
    except re.error as exc:  # pragma: no cover - shipped file
        raise ConfigError(f"bad catalogue regex for {item.get('path')!r}: {exc}") from exc
    return Validator(
        content=pattern,
        min_matches=int(item.get("min_matches", 1)),
        content_type=tuple(str(token) for token in item.get("content_type", ())),
        json_keys=tuple(str(key) for key in item.get("json_keys", ())),
        magic=tuple(bytes.fromhex(str(h)) for h in item.get("magic", ())),
    )


def _expand_backups(table: dict[str, Any]) -> list[ProbeEntry]:
    """
    Args:
        table (dict[str, Any]): The ``[backups]`` table (``check``,
            ``basenames``, ``suffixes``).

    Returns:
        list[ProbeEntry]: One entry per basename x suffix, or ``[]`` when the
            table is absent.
    """
    if not table:
        return []
    check_id = str(table["check"])
    basenames = [str(name) for name in table["basenames"]]
    suffixes = [str(suffix) for suffix in table["suffixes"]]
    out: list[ProbeEntry] = []
    for base in basenames:
        for suffix in suffixes:
            out.append(_backup_entry(f"{base}{suffix}", suffix, check_id))
    return out


def _backup_entry(path: str, suffix: str, check_id: str) -> ProbeEntry:
    """
    Build a backup :class:`ProbeEntry`, choosing the validator from the suffix.

    Args:
        path (str): The path to probe.
        suffix (str): The file suffix (``.zip``, ``.sql``, ``.bak``, ...).
        check_id (str): The backup check id.

    Returns:
        ProbeEntry: An archive-magic, SQL-content, or source-marker validator
            depending on ``suffix``; ``.sql`` / ``.sql.gz`` are HIGH severity.
    """
    magic = _BACKUP_ARCHIVE_MAGIC.get(suffix, ())
    if magic:
        validator = Validator(magic=magic)
        confidence = Confidence.HIGH
    elif suffix == ".sql":
        validator = Validator(content=_BACKUP_SQL_RE)
        confidence = Confidence.HIGH
    else:
        validator = Validator(content=_BACKUP_SOURCE_RE)
        confidence = Confidence.MEDIUM
    severity = Severity.HIGH if suffix in _HIGH_BACKUP_SUFFIXES else Severity.MEDIUM
    return ProbeEntry(
        path=path,
        family="backup",
        check_id=check_id,
        severity=severity,
        confidence=confidence,
        title=f"Backup or dump file exposed ({path})",
        description=_DEFAULT_DESCRIPTION["backup"],
        validator=validator,
        redaction="generic",
    )


@lru_cache(maxsize=1)
def backup_spec() -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    """
    Returns:
        tuple[str, tuple[str, ...], tuple[str, ...]]: The backup check id, the
            configured suffixes, and the configured basenames — the probe
            appends the host label to these at scan time. Cached for the
            process.
    """
    text = files(_PACKAGE).joinpath(_FILE).read_text(encoding="utf-8")
    table = tomllib.loads(text).get("backups", {})
    return (
        str(table.get("check", "disclosure.backup.file-exposed")),
        tuple(str(suffix) for suffix in table.get("suffixes", ())),
        tuple(str(name) for name in table.get("basenames", ())),
    )


def build_backup_entry(path: str, suffix: str) -> ProbeEntry:
    """
    Args:
        path (str): The host-label-derived path (e.g. ``"example.sql"``).
        suffix (str): Its suffix.

    Returns:
        ProbeEntry: A backup entry for a basename the probe derives at scan
            time.
    """
    return _backup_entry(path, suffix, backup_spec()[0])


def _validate(entries: list[ProbeEntry]) -> None:
    """
    Args:
        entries (list[ProbeEntry]): The fully expanded catalogue.

    Raises:
        ConfigError: If the catalogue is empty or an entry names a check id not
            in ``PROBE_CHECK_IDS``.
    """
    if not entries:  # pragma: no cover - shipped file
        raise ConfigError("disclosure catalogue is empty")
    for entry in entries:
        if entry.check_id not in PROBE_CHECK_IDS:  # pragma: no cover - shipped file
            raise ConfigError(
                f"catalogue entry {entry.path!r} names unknown check {entry.check_id!r}"
            )
