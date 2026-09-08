"""
Reporters render the technology inventory — RF-13, RF-14.
"""

from __future__ import annotations

from tests.support import make_finding, make_result
from webvigil.core.findings import Severity
from webvigil.core.technology import DetectionMethod, Technology
from webvigil.reporting import get_reporter, load_result
from webvigil.reporting.sarif import SarifReporter

_TECHS = (
    Technology(
        name="jquery",
        version="1.12.4",
        detection=DetectionMethod.FILENAME,
        source_url="https://example.com/jquery-1.12.4.min.js",
        vulnerable=True,
        advisories=("CVE-2020-11022",),
    ),
    Technology(
        name="react",
        version="18.2.0",
        detection=DetectionMethod.URI,
        source_url="https://example.com/react.js",
    ),
)


def _result():
    return make_result(
        make_finding(check_id="deps.js.vulnerable-library", severity=Severity.MEDIUM),
        technologies=_TECHS,
    )


def test_json_round_trips_the_inventory(tmp_path) -> None:
    path = tmp_path / "r.json"
    path.write_text(get_reporter("json").render(_result()), "utf-8")
    assert load_result(path).technologies == _TECHS


def test_html_has_a_detected_technologies_section() -> None:
    html = get_reporter("html").render(_result())
    assert "Detected technologies" in html
    assert "jquery" in html and "1.12.4" in html
    assert "Vulnerable" in html and "CVE-2020-11022" in html
    assert "unknown" in html or "18.2.0" in html


def test_markdown_has_a_detected_technologies_section() -> None:
    md = get_reporter("md").render(_result())
    assert "## Detected technologies" in md
    assert "| jquery | 1.12.4 |" in md
    assert "**Vulnerable**" in md


def test_no_section_when_inventory_is_empty() -> None:
    plain = make_result(make_finding())
    assert "Detected technologies" not in get_reporter("html").render(plain)
    assert "Detected technologies" not in get_reporter("md").render(plain)


def test_sarif_has_the_vulnerable_library_rule() -> None:
    document = SarifReporter().to_dict(_result())
    rule_ids = {rule["id"] for rule in document["runs"][0]["tool"]["driver"]["rules"]}
    assert "deps.js.vulnerable-library" in rule_ids
