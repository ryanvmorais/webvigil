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
from webvigil.core.findings import EvidenceItem, Finding, Severity
from webvigil.core.result import LoginSummary, ScanResult
from webvigil.reporting import get_reporter, load_result, sort_findings
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


def test_json_carries_the_login_summary_and_round_trips() -> None:
    """``metadata.login`` is ``null`` without a login and the two facts with one (spec 019)."""
    assert json.loads(get_reporter("json").render(_result()))["metadata"]["login"] is None

    logged = make_result(login=LoginSummary(relogins=2, session_lost=False))
    rendered = get_reporter("json").render(logged)
    assert json.loads(rendered)["metadata"]["login"] == {
        "relogins": 2,
        "session_lost": False,
        "confirmed": True,
    }
    assert load_result_from_string(rendered) == logged


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


@pytest.mark.parametrize(
    ("severity", "level"),
    [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
    ],
)
def test_every_severity_has_its_sarif_level(severity: Severity, level: str) -> None:
    """Code scanning sorts and gates on ``level``: each of the five severities, one row each."""
    document = SarifReporter().to_dict(make_result(make_finding(severity=severity)))
    (result,) = document["runs"][0]["results"]
    assert result["level"] == level


def test_sarif_carries_partial_fingerprints() -> None:
    """Each SARIF result carries its finding's fingerprint, the key a baseline diff matches on."""
    result = _result()
    document = SarifReporter().to_dict(result)
    by_rule = {r["ruleId"]: r["partialFingerprints"] for r in document["runs"][0]["results"]}
    assert by_rule == {f.check_id: {"webvigil/v1": f.fingerprint} for f in result.findings}
    assert len({fp["webvigil/v1"] for fp in by_rule.values()}) == 3


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
    # a header (or a cookie) is a member of the response, not a parameter of the request
    header = SarifReporter().to_dict(make_result(make_finding()))["runs"][0]["results"][0]
    (member,) = header["locations"][0]["logicalLocations"]
    assert (member["name"], member["kind"]) == ("Content-Security-Policy", "member")


def test_html_is_self_contained() -> None:
    """The HTML report inlines its CSS and pulls in no external link, script, or import."""
    html = get_reporter("html").render(_result())
    assert "<style>" in html
    assert "<link " not in html
    assert "<script" not in html
    assert "@import" not in html


def test_html_header_carries_the_logo_as_inline_svg() -> None:
    """The logo is an inline, decorative SVG before the title; no image is loaded for it."""
    html = get_reporter("html").render(_result())
    assert '<h1><svg class="logo"' in html
    assert 'aria-hidden="true"' in html.split("</svg>")[0]
    assert "<img" not in html


def test_html_escapes_evidence() -> None:
    """The site's markup in a title or the evidence is shown as text, never parsed as HTML."""
    finding = make_finding(check_id="x.y").model_copy(
        update={
            "title": "x.y finding <b>bold</b>",
            "evidence": (EvidenceItem.of("body", '<img src=x onerror="alert(1)">'),),
        }
    )
    html = get_reporter("html").render(make_result(finding))
    assert "x.y finding &lt;b&gt;bold&lt;/b&gt;" in html
    assert "&lt;img src=x onerror=&#34;alert(1)&#34;&gt;" in html
    assert "<b>bold</b>" not in html and "<img src=x" not in html


def test_html_links_only_http_references() -> None:
    """A reference is a link only when it is ``http(s)``; any other scheme is escaped text."""
    finding = make_finding(
        references=(
            "https://example.org/ok",
            "javascript:alert(1)",
            'data:text/html,<script>alert("x")</script>',
        )
    )
    html = get_reporter("html").render(make_result(finding))
    assert '<a href="https://example.org/ok">https://example.org/ok</a>' in html
    assert 'href="javascript:' not in html
    assert 'href="data:' not in html
    assert "javascript:alert(1)" in html  # still shown, as text
    assert "data:text/html,&lt;script&gt;" in html


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


def _ordering_case() -> tuple[Finding, ...]:
    """
    Returns:
        tuple[Finding, ...]: Findings in their expected display order: severity first (highest
            first), then check id, then URL, then the sub-location.
    """
    return (
        make_finding(check_id="z.last-id", severity=Severity.CRITICAL, dedup_key="1"),
        make_finding(check_id="a.first-id", severity=Severity.HIGH, url="https://example.com/b"),
        # its sub-location ("z") sorts after the next ones' ("a", "b"): only the URL puts it first
        make_finding(
            check_id="b.second-id", severity=Severity.HIGH, url="https://example.com/a", param="z"
        ),
        make_finding(
            check_id="b.second-id", severity=Severity.HIGH, url="https://example.com/b", param="a"
        ),
        make_finding(
            check_id="b.second-id", severity=Severity.HIGH, url="https://example.com/b", param="b"
        ),
        make_finding(check_id="a.first-id", severity=Severity.INFO, dedup_key="2"),
    )


def test_findings_are_shown_most_severe_first_then_by_check_url_and_location() -> None:
    """A total order: every tie of the key before it is broken by the next one."""
    expected = list(_ordering_case())
    assert sort_findings(tuple(reversed(expected))) == expected


@pytest.mark.parametrize("fmt", ["html", "md"])
def test_the_text_reports_list_findings_in_that_order_whatever_the_input_order(fmt: str) -> None:
    """The checks finish in any order, so two runs of one scan must still read the same."""
    findings = _ordering_case()
    forward = get_reporter(fmt).render(make_result(*findings))
    assert forward == get_reporter(fmt).render(make_result(*reversed(findings)))
    # the CRITICAL finding leads although its check id sorts last
    assert forward.index("z.last-id finding") < forward.index("a.first-id finding")


def test_unknown_format_raises() -> None:
    """``get_reporter`` with an unknown format raises ``ValueError``."""
    with pytest.raises(ValueError, match="unknown report format"):
        get_reporter("pdf")


# ---------------------------------------------------------------------------
# The report's schema version (the 1.0 compatibility contract)
# ---------------------------------------------------------------------------


def test_the_json_report_starts_with_its_schema_version_and_round_trips() -> None:
    """``schema_version`` leads the document, is 1 today and survives a round trip."""
    result = make_result(make_finding(check_id="csrf.form.no-token"))
    rendered = get_reporter("json").render(result)

    document = json.loads(rendered)
    assert next(iter(document)) == "schema_version" and document["schema_version"] == 1
    assert load_result_from_string(rendered) == result


def test_a_report_without_a_schema_version_reads_as_version_1() -> None:
    """A report written before the field existed (a pre-1.0 one) still loads."""
    document = json.loads(get_reporter("json").render(_result()))
    del document["schema_version"]
    assert load_result_from_string(json.dumps(document)).schema_version == 1


def test_a_report_from_a_newer_schema_is_refused_with_a_message_that_says_to_upgrade() -> None:
    """Reading a schema this WebVigil does not know is an error, never a silent misread."""
    document = json.loads(get_reporter("json").render(_result()))
    document["schema_version"] = 2
    with pytest.raises(ValueError, match=r"schema 2.*upgrade WebVigil"):
        load_result_from_string(json.dumps(document))
