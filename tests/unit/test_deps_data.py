"""
The vendored Retire.js data ships in the package and loads from there — RF-06, Risks.

These run against the real ``retirejs.json`` / ``PROVENANCE.json`` in the
package (via :mod:`importlib.resources`), so they double as a shape check on
whatever the refresh script last wrote.
"""

from __future__ import annotations

from webvigil.checks.deps import _data


def test_database_loads_from_the_installed_package() -> None:
    """``load_raw_db`` reads the vendored file and returns a non-empty ``components`` map."""
    db = _data.load_raw_db()
    assert set(db) >= {"_note", "components"}
    assert db["components"], "the vendored database has no components"
    jquery = db["components"]["jquery"]
    assert jquery["extractors"]
    assert jquery["vulnerabilities"]


def test_every_vulnerability_has_the_normalised_shape() -> None:
    """Every entry has exactly the six normalised keys, with list identifiers and int CWE ids."""
    for name, component in _data.load_raw_db()["components"].items():
        for vuln in component["vulnerabilities"]:
            assert set(vuln) == {
                "ranges",
                "severity",
                "identifiers",
                "summary",
                "cwe",
                "info",
            }, name
            assert isinstance(vuln["identifiers"], list)
            assert all(isinstance(c, int) for c in vuln["cwe"])


def test_provenance_parses() -> None:
    """``PROVENANCE.json`` parses into a :class:`Provenance` with the expected licence."""
    provenance = _data.load_provenance()
    assert provenance.license == "Apache-2.0"
    assert "retire.js" in provenance.source_url.lower()
