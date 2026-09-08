"""
ScanResult ⇄ DB rows round-trips losslessly — RF-19.

``store_result`` writes an engine :class:`ScanResult` into the ``scan`` /
``finding`` rows; ``rows_to_result`` rebuilds it. The tests seed a ``scan`` row,
run a result through both, and assert the rebuilt result renders byte-identically
to the original — plus the ``build_scan_config`` direction, which turns a stored
scan's options back into a :class:`ScanConfig`.
"""

from __future__ import annotations

from sqlalchemy import Engine
from sqlmodel import Session, select

from tests.support import make_finding, make_result
from webvigil.api.db import Finding as FindingRow
from webvigil.api.db import Scan, ScanStatus
from webvigil.api.mapping import build_scan_config, rows_to_result, store_result
from webvigil.core.findings import ScanMode, Severity
from webvigil.reporting import get_reporter


def _seed_scan(engine: Engine, mode: str = "passive", authorized_by: str | None = None) -> int:
    """
    Args:
        engine (Engine): The per-test database engine.
        mode (str): The scan mode column value. Defaults to ``"passive"``.
        authorized_by (str | None): The authorisation column value, if any.

    Returns:
        int: The id of the inserted RUNNING scan row.
    """
    with Session(engine) as session:
        scan = Scan(
            target="https://example.com/",
            mode=mode,
            scope="host",
            status=ScanStatus.RUNNING,
            authorized_by=authorized_by,
            options={"max_pages": 3, "delay_ms": 10, "disabled_checks": ["tls.https"]},
        )
        session.add(scan)
        session.commit()
        assert scan.id is not None
        return scan.id


def test_store_then_rebuild_is_byte_identical(web_engine: Engine) -> None:
    """A result stored and rebuilt renders to the same JSON, and the scan flips to COMPLETED."""
    scan_id = _seed_scan(web_engine)
    result = make_result(
        make_finding(check_id="tls.https", severity=Severity.HIGH, dedup_key="no-https"),
        make_finding(check_id="http.headers.csp", severity=Severity.MEDIUM),
    )

    with Session(web_engine) as session:
        store_result(session, scan_id, result)

    with Session(web_engine) as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None and scan.status == ScanStatus.COMPLETED
        findings = list(session.exec(select(FindingRow).where(FindingRow.scan_id == scan_id)))
        rebuilt = rows_to_result(scan, findings)

    assert get_reporter("json").render(rebuilt) == get_reporter("json").render(result)


def test_technologies_round_trip_through_the_rows(web_engine: Engine) -> None:
    """The technology inventory survives the store / rebuild round-trip on the scan row."""
    from webvigil.core.technology import DetectionMethod, Technology

    scan_id = _seed_scan(web_engine)
    result = make_result(
        make_finding(check_id="deps.js.vulnerable-library"),
        technologies=(
            Technology(
                name="jquery",
                version="1.7.1",
                detection=DetectionMethod.FILENAME,
                source_url="https://example.com/jquery-1.7.1.min.js",
                vulnerable=True,
                advisories=("CVE-2011-4969",),
            ),
        ),
    )
    with Session(web_engine) as session:
        store_result(session, scan_id, result)
    with Session(web_engine) as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None
        rebuilt = rows_to_result(scan, [])
    assert rebuilt.technologies == result.technologies


def test_missing_technologies_column_reads_as_empty(web_engine: Engine) -> None:
    """A pre-spec-004 scan row with a NULL ``technologies`` column rebuilds to an empty tuple."""
    scan_id = _seed_scan(web_engine)
    with Session(web_engine) as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None
        scan.technologies = None  # type: ignore[assignment]  # simulate a pre-004 row
        rebuilt = rows_to_result(scan, [])
    assert rebuilt.technologies == ()


def test_build_scan_config_applies_options() -> None:
    """``build_scan_config`` maps a stored scan's mode, scope, options and authorisation back
    into a :class:`ScanConfig`."""
    scan = Scan(
        target="https://example.com/",
        mode="active",
        scope="subdomains",
        status=ScanStatus.QUEUED,
        authorized_by="Jane / #1",
        options={"max_pages": 12, "delay_ms": 50, "disabled_checks": ["http.headers.hsts"]},
    )
    config = build_scan_config(scan)
    assert config.scan.mode == ScanMode.ACTIVE
    assert config.scan.max_pages == 12
    assert config.http.delay_ms == 50
    assert config.checks.disabled == ["http.headers.hsts"]
    assert config.active is not None and config.active.authorized_by == "Jane / #1"
