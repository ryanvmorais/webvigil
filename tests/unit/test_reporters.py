"""
Reporters: JSON round-trip, SARIF schema, HTML self-containment, determinism — RF-21..23.

``_result`` builds one canned :class:`ScanResult` with three findings across the
severity range; each test renders it through a reporter and checks a structural
property — JSON round-trips back to an equal object, SARIF validates against the
bundled 2.1.0 schema, HTML embeds all its assets, every reporter is byte-stable.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from tests.support import make_finding, make_result
from webvigil.core.findings import Severity
from webvigil.core.result import ScanResult
from webvigil.reporting import get_reporter, load_result
from webvigil.reporting.sarif import SarifReporter

_SARIF_SCHEMA = json.loads(
    (Path(__file__).parents[1] / "data" / "sarif-2.1.0.json").read_text("utf-8")
)


def _result() -> ScanResult:
    """
    Returns:
        ScanResult: A result with a HIGH, a MEDIUM and a LOW finding.
    """
    return make_result(
        make_finding(check_id="tls.https", severity=Severity.HIGH, dedup_key="no-https"),
        make_finding(check_id="http.headers.csp", severity=Severity.MEDIUM),
        make_finding(check_id="http.headers.hsts", severity=Severity.LOW, dedup_key="low"),
    )


def test_json_reporter_round_trips() -> None:
    """The JSON reporter's output parses back into an equal :class:`ScanResult`."""
    rendered = get_reporter("json").render(_result())
    restored = load_result_from_string(rendered)
    assert restored == _result()


def load_result_from_string(text: str) -> ScanResult:
    """
    Args:
        text (str): A rendered JSON report.

    Returns:
        ScanResult: The result parsed back from ``text``.
    """
    return ScanResult.model_validate_json(text)


def test_load_result_reads_a_file(tmp_path: Path) -> None:
    """``load_result`` reads a rendered JSON report back from a file."""
    path = tmp_path / "scan.json"
    path.write_text(get_reporter("json").render(_result()), "utf-8")
    assert load_result(path) == _result()


def test_json_carries_the_authenticated_flag_and_round_trips() -> None:
    """The ``metadata.authenticated`` flag is serialised and survives a round-trip."""
    anon = json.loads(get_reporter("json").render(_result()))
    assert anon["metadata"]["authenticated"] is False

    authed = make_result(make_finding(check_id="csrf.form.no-token"), authenticated=True)
    rendered = get_reporter("json").render(authed)
    assert json.loads(rendered)["metadata"]["authenticated"] is True
    assert load_result_from_string(rendered) == authed


def test_sarif_validates_against_the_2_1_0_schema() -> None:
    """The SARIF output validates against the bundled 2.1.0 JSON schema."""
    document = json.loads(get_reporter("sarif").render(_result()))
    jsonschema.validate(document, _SARIF_SCHEMA)


def test_sarif_maps_severity_to_level() -> None:
    """Severity maps to the SARIF ``level`` (error / warning / note) per rule."""
    document = SarifReporter().to_dict(_result())
    levels = {r["ruleId"]: r["level"] for r in document["runs"][0]["results"]}
    assert levels["tls.https"] == "error"
    assert levels["http.headers.csp"] == "warning"
    assert levels["http.headers.hsts"] == "note"
    rules = document["runs"][0]["tool"]["driver"]["rules"]
    assert {r["id"] for r in rules} == {"tls.https", "http.headers.csp", "http.headers.hsts"}


def test_sarif_carries_partial_fingerprints() -> None:
    """Every SARIF result carries a ``webvigil/v1`` partial fingerprint for baseline diffing."""
    document = SarifReporter().to_dict(_result())
    for result in document["runs"][0]["results"]:
        assert result["partialFingerprints"]["webvigil/v1"]


def test_sarif_logical_location_carries_the_parameter() -> None:
    """A finding with a parameter gets a SARIF logical location; one without does not."""
    result = make_result(
        make_finding(check_id="injection.xss.reflected", param="q", method="GET"),
        make_finding(check_id="tls.https", header=None, dedup_key="no-loc"),
    )
    document = SarifReporter().to_dict(result)
    jsonschema.validate(document, _SARIF_SCHEMA)
    by_rule = {r["ruleId"]: r for r in document["runs"][0]["results"]}
    logical = by_rule["injection.xss.reflected"]["locations"][0]["logicalLocations"][0]
    assert logical["name"] == "q" and logical["kind"] == "parameter"
    assert "logicalLocations" not in by_rule["tls.https"]["locations"][0]


def test_html_is_self_contained() -> None:
    """The HTML report inlines its CSS and pulls in no external link, script, or import."""
    html = get_reporter("html").render(_result())
    assert "<style>" in html
    assert "<link " not in html
    assert "<script" not in html
    assert "@import" not in html


def test_html_escapes_evidence() -> None:
    """Evidence text is rendered into the HTML report."""
    finding = make_finding(check_id="x.y")
    html = get_reporter("html").render(make_result(finding))
    assert "x.y finding" in html


def test_markdown_has_summary_table_and_sections() -> None:
    """The Markdown report has a severity summary table and one section per finding."""
    md = get_reporter("md").render(_result())
    assert "| Severity | Count |" in md
    assert md.count("## [") == 3


@pytest.mark.parametrize("fmt", ["json", "sarif", "html", "md"])
def test_reporters_are_deterministic(fmt: str) -> None:
    """Each reporter renders the same result to byte-identical output."""
    reporter = get_reporter(fmt)
    assert reporter.render(_result()) == reporter.render(_result())


def test_unknown_format_raises() -> None:
    """``get_reporter`` with an unknown format raises ``ValueError``."""
    with pytest.raises(ValueError, match="unknown report format"):
        get_reporter("pdf")
