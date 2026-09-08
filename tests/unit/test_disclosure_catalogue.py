"""
The curated probe catalogue loads, expands, and validates — RF-05, ADR-4, Risks.

Runs against the real shipped ``paths.toml`` (via :mod:`importlib.resources`),
so these double as a guard on whatever the file currently declares — the counts
are lower bounds, not fixed numbers.
"""

from __future__ import annotations

import pytest

from webvigil.checks.disclosure.catalogue import (
    PROBE_CHECK_IDS,
    Validator,
    build_backup_entry,
    load_catalogue,
)
from webvigil.core.findings import Severity

# ---------------------------------------------------------------------------
# Loading and expansion
# ---------------------------------------------------------------------------


def test_catalogue_loads_from_the_installed_package() -> None:
    """The shipped file loads and every entry names a known probe check."""
    catalogue = load_catalogue()
    assert len(catalogue) >= 60
    assert all(entry.check_id in PROBE_CHECK_IDS for entry in catalogue)


def test_every_family_is_represented() -> None:
    """Every non-sourcemap probe family appears in the loaded catalogue."""
    families = {entry.family for entry in load_catalogue()}
    assert families == {"vcs", "config", "manifest", "backup", "debug"}


def test_backups_are_expanded_to_the_cross_product() -> None:
    """The ``[backups]`` table expands to one entry per basename x suffix."""
    backups = [entry for entry in load_catalogue() if entry.family == "backup"]
    assert len(backups) >= 24
    assert any(e.path.endswith(".sql") and e.severity is Severity.HIGH for e in backups)
    assert any(e.path.endswith(".bak") and e.severity is Severity.MEDIUM for e in backups)


def test_git_directory_entry_accepts_403() -> None:
    """The ``.git/`` entry treats a ``403`` as a hit (a locked-down but present directory)."""
    git_dir = next(entry for entry in load_catalogue() if entry.path == ".git/")
    assert 403 in git_dir.ok_status


def test_build_backup_entry_for_a_host_label() -> None:
    """A host-label backup name gets a backup entry with the suffix's severity."""
    entry = build_backup_entry("example.sql", ".sql")
    assert entry.family == "backup"
    assert entry.severity is Severity.HIGH
    assert entry.check_id == "disclosure.backup.file-exposed"


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def test_dotenv_entry_requires_two_key_value_lines() -> None:
    """The ``.env`` validator passes on multiple ``KEY=value`` lines, fails on prose."""
    dotenv = next(entry for entry in load_catalogue() if entry.path == ".env")
    assert dotenv.redaction == "dotenv"
    good = "DEBUG=1\nSECRET_KEY=abc\nDB_HOST=localhost\n"
    assert dotenv.validator.passes(body=good, raw=good.encode(), content_type="text/plain")
    assert not dotenv.validator.passes(
        body="just one line here", raw=b"just one line here", content_type="text/plain"
    )


def test_json_validator_needs_a_matching_object_key() -> None:
    """``json_keys`` passes only when the body is a JSON object with one of the named keys."""
    v = Validator(json_keys=("dependencies", "name"))
    assert v.passes(body='{"name": "x"}', raw=b"", content_type="application/json")
    assert not v.passes(body='{"other": 1}', raw=b"", content_type="application/json")
    assert not v.passes(body="not json", raw=b"", content_type="application/json")


def test_magic_validator_matches_a_byte_prefix() -> None:
    """``magic`` passes when the raw body starts with one of the configured byte prefixes."""
    v = Validator(magic=(b"PK\x03\x04",))
    assert v.passes(body="", raw=b"PK\x03\x04rest", content_type="application/zip")
    assert not v.passes(body="", raw=b"<html>", content_type="text/html")


@pytest.mark.parametrize("entry", load_catalogue())
def test_every_content_regex_compiled(entry: object) -> None:
    """Every entry's ``content`` regex either is absent or compiled to a real pattern."""
    validator = entry.validator  # type: ignore[attr-defined]
    assert validator.content is None or validator.content.pattern
