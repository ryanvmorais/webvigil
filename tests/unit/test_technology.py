"""
The technology inventory: Observations dedup/order and ScanResult round-trip — RF-12, RF-14.
"""

from __future__ import annotations

from datetime import UTC, datetime

from webvigil.core.context import Detection, Observations
from webvigil.core.findings import ScanMode, Severity
from webvigil.core.result import ScanMetadata, ScanResult
from webvigil.core.target import Scope
from webvigil.core.technology import DetectionMethod, Technology


def _tech(
    name: str, version: str | None, *, method: DetectionMethod = DetectionMethod.FILENAME
) -> Technology:
    return Technology(
        name=name, version=version, detection=method, source_url=f"https://x/{name}.js"
    )


def test_observations_dedup_on_name_and_version() -> None:
    obs = Observations()
    obs.add_technology(_tech("jquery", "1.12.4"))
    obs.add_technology(_tech("jquery", "1.12.4", method=DetectionMethod.URI))  # ignored
    obs.add_technology(_tech("jquery", "3.6.0"))
    obs.add_technology(_tech("bootstrap", None))

    got = obs.technologies
    assert [(t.name, t.version) for t in got] == [
        ("bootstrap", None),
        ("jquery", "1.12.4"),
        ("jquery", "3.6.0"),
    ]
    assert got[1].detection is DetectionMethod.FILENAME  # first write wins


def test_observations_warnings_accumulate() -> None:
    obs = Observations()
    obs.add_warning("one")
    obs.add_warning("two")
    assert obs.warnings == ["one", "two"]


def test_detection_is_frozen_and_hashable() -> None:
    d = Detection(
        "jquery", "1.12.4", DetectionMethod.FILENAME, "https://x/jquery.js", "jquery-1.12.4.min.js"
    )
    assert {d, d} == {d}


def test_scan_result_round_trips_technologies() -> None:
    meta = ScanMetadata(
        target="https://example.com/",
        mode=ScanMode.PASSIVE,
        scope=Scope.HOST,
        tool_version="9.9.9",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        finished_at=datetime(2026, 1, 1, tzinfo=UTC),
        pages_scanned=1,
        counts={s.name: 0 for s in Severity},
    )
    result = ScanResult(
        metadata=meta,
        findings=(),
        technologies=(
            Technology(
                name="jquery",
                version="1.12.4",
                detection=DetectionMethod.FILENAME,
                source_url="https://example.com/jquery-1.12.4.min.js",
                vulnerable=True,
                advisories=("CVE-2020-11022",),
            ),
        ),
    )
    reloaded = ScanResult.model_validate_json(result.model_dump_json())
    assert reloaded == result
    assert reloaded.technologies[0].vulnerable is True
