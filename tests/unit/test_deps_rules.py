"""
RetireJsRules: the real DB compiles, and identify() reads each source — RF-05, RF-06.

One test runs against the real vendored database (it must always compile); the
rest use the ``rules`` fixture over ``tests/data/retirejs-mini.json`` so each
detection source can be asserted in isolation.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path

import pytest

from webvigil.checks.deps._data import Provenance
from webvigil.checks.deps.rules import RetireJsRules
from webvigil.core.technology import DetectionMethod

_MINI = Path(__file__).parent.parent / "data" / "retirejs-mini.json"
_PROVENANCE = Provenance(
    source_url="https://example/retire.js",
    retrieved=date(2026, 1, 1),
    license="Apache-2.0",
    attribution="test",
)


@pytest.fixture
def rules() -> RetireJsRules:
    """
    Returns:
        RetireJsRules: Rules compiled from the mini database.
    """
    return RetireJsRules.from_raw(json.loads(_MINI.read_text("utf-8")), _PROVENANCE)


def test_the_vendored_database_loads_and_parses() -> None:
    """The real vendored database compiles, and a filename detection works end to end against it."""
    real = RetireJsRules.load()
    # Loading compiles every Python-compatible extractor (JS-only constructs are skipped)
    # and parses the vulnerability entries.
    entries = real.vulnerabilities_for("jquery")
    assert entries
    assert any(entry.identifiers for entry in entries)
    for entry in entries:
        assert all(isinstance(c, int) for c in entry.cwe)
        assert all(url.startswith("http") for url in entry.info)
    # A real detection end to end against the vendored data.
    found = real.identify(url="https://target/js/jquery-1.7.1.min.js")
    assert any(d.name == "jquery" and d.version == "1.7.1" for d in found)


def test_identify_from_filename(rules: RetireJsRules) -> None:
    """A ``jquery-1.12.4.min.js`` path yields a FILENAME detection."""
    found = rules.identify(url="https://target/static/jquery-1.12.4.min.js")
    assert ("jquery", "1.12.4", DetectionMethod.FILENAME) in [
        (d.name, d.version, d.method) for d in found
    ]


def test_identify_from_uri_path(rules: RetireJsRules) -> None:
    """A ``/3.4.1/jquery.min.js`` CDN path yields a URI detection."""
    found = rules.identify(url="https://cdn.example/3.4.1/jquery.min.js")
    assert ("jquery", "3.4.1", DetectionMethod.URI) in [
        (d.name, d.version, d.method) for d in found
    ]


def test_identify_from_filecontent_banner(rules: RetireJsRules) -> None:
    """A ``/*! jQuery v3.4.1 */`` banner in a body yields a FILECONTENT detection."""
    body = "/*! jQuery v3.4.1 | (c) JS Foundation */\n!function(){}();"
    found = rules.identify(url="https://target/app.js", body=body)
    jquery = [d for d in found if d.name == "jquery"]
    assert jquery and jquery[0].version == "3.4.1"
    assert jquery[0].method is DetectionMethod.FILECONTENT


def test_identify_from_hash(rules: RetireJsRules) -> None:
    """An exact SHA-1 match of a body yields a HASH detection with the exact version."""
    body = "!function(){/* minified lib */}();"
    digest = hashlib.sha1(body.encode()).hexdigest()
    raw = json.loads(_MINI.read_text("utf-8"))
    raw["components"]["lodash"]["extractors"]["hashes"] = {digest: "3.10.1"}
    rules = RetireJsRules.from_raw(raw, _PROVENANCE)

    found = rules.identify(url="https://target/vendor/lib.js", body=body)
    lodash = [d for d in found if d.name == "lodash" and d.method is DetectionMethod.HASH]
    assert lodash and lodash[0].version == "3.10.1"


def test_identify_returns_nothing_for_an_unknown_resource(rules: RetireJsRules) -> None:
    """A resource matching no extractor and no hash yields nothing."""
    assert rules.identify(url="https://target/static/app.css", body="body{}") == []
