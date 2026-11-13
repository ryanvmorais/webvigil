"""
A report read back from a file: the size of the file, the size of each field, the schema version
and the severity counts.

``webvigil report`` reloads a JSON report that someone else may have written, so nothing in it
is taken on trust. The tests write files to ``tmp_path`` and lower ``MAX_REPORT_BYTES`` with
``monkeypatch`` instead of writing 256 MiB; the field tests build the models directly, since the
same bound applies when a check builds a finding and when a file is read.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

import webvigil.reporting as reporting
from tests.support import make_finding, make_result
from webvigil.cli import app as app_mod
from webvigil.cli._exit import ExitCode
from webvigil.core.bounded import (
    NAME_MAX_CHARS,
    TEXT_MAX_CHARS,
    TRUNCATION_MARKER,
    URL_MAX_CHARS,
    truncate,
)
from webvigil.core.findings import EvidenceItem, Location, Severity
from webvigil.core.result import CheckError, ScanResult
from webvigil.core.technology import DetectionMethod, Technology
from webvigil.reporting import get_reporter, load_result

runner = CliRunner()


def _write(tmp_path: Path, result: ScanResult) -> Path:
    """
    Args:
        tmp_path (Path): The test's temporary directory.
        result (ScanResult): The result to save.

    Returns:
        Path: A JSON report of ``result``.
    """
    path = tmp_path / "scan.json"
    path.write_text(get_reporter("json").render(result), "utf-8")
    return path


def _document(**update: object) -> dict[str, object]:
    """
    Args:
        **update (object): Top-level keys of the report to replace.

    Returns:
        dict[str, object]: A JSON report with one finding, as parsed JSON.
    """
    document: dict[str, object] = json.loads(
        get_reporter("json").render(make_result(make_finding()))
    )
    document.update(update)
    return document


# ---------------------------------------------------------------------------
# File size
# ---------------------------------------------------------------------------


def test_a_file_over_the_limit_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """One byte past ``MAX_REPORT_BYTES`` is refused before parsing, with the limit in MiB."""
    path = _write(tmp_path, make_result(make_finding()))
    size = path.stat().st_size
    monkeypatch.setattr(reporting, "MAX_REPORT_BYTES", size - 1)
    with pytest.raises(ValueError, match=r"larger than \d+ MiB"):
        load_result(path)


def test_a_file_at_the_limit_is_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write(tmp_path, make_result(make_finding()))
    monkeypatch.setattr(reporting, "MAX_REPORT_BYTES", path.stat().st_size)
    assert len(load_result(path).findings) == 1


def test_report_on_a_file_over_the_limit_exits_4_without_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path, make_result(make_finding()))
    monkeypatch.setattr(reporting, "MAX_REPORT_BYTES", 16)

    result = runner.invoke(app_mod.app, ["report", str(path), "--format", "md"])

    assert result.exit_code == ExitCode.OPERATIONAL
    # Rich wraps the line at the terminal width.
    assert "the most `webvigil report` reads" in " ".join(result.stderr.split())
    assert "Traceback" not in result.stderr


# ---------------------------------------------------------------------------
# Field bounds
# ---------------------------------------------------------------------------


def test_truncate_cuts_and_marks_and_leaves_a_cut_value_alone() -> None:
    """Idempotent: a value already cut, marker included, reads back as it is."""
    cut = truncate("x" * 100, 10)
    assert cut == "x" * 10 + TRUNCATION_MARKER
    assert truncate(cut, 10) == cut
    assert truncate("x" * (10 + len(TRUNCATION_MARKER)), 10) == "x" * (10 + len(TRUNCATION_MARKER))


def test_every_free_text_field_of_a_finding_is_bounded() -> None:
    finding = make_finding().model_copy(
        update={
            "title": "t" * 50_000,
            "description": "d" * 50_000,
            "remediation": "r" * 50_000,
            "references": ("https://example.org/" + "a" * 100_000,),
        }
    )
    # model_copy does not validate; the bound applies when a model is built or read.
    bounded = type(finding).model_validate(finding.model_dump())
    assert bounded.title == "t" * NAME_MAX_CHARS + TRUNCATION_MARKER
    assert bounded.description == "d" * TEXT_MAX_CHARS + TRUNCATION_MARKER
    assert bounded.remediation == "r" * TEXT_MAX_CHARS + TRUNCATION_MARKER
    assert len(bounded.references[0]) == URL_MAX_CHARS + len(TRUNCATION_MARKER)


def test_a_location_and_evidence_built_directly_are_bounded() -> None:
    """``EvidenceItem(...)`` gets the bound of ``EvidenceItem.of`` and reads it back unchanged."""
    location = Location(url="https://example.com/" + "p" * 100_000, cookie="c" * 5000)
    assert len(location.url) == URL_MAX_CHARS + len(TRUNCATION_MARKER)
    assert location.cookie == "c" * NAME_MAX_CHARS + TRUNCATION_MARKER

    direct = EvidenceItem(label="l" * 5000, content="e" * 10_000)
    assert direct == EvidenceItem.of("l" * 5000, "e" * 10_000)
    assert direct.content.endswith("\n...[truncated]")
    assert EvidenceItem.model_validate(direct.model_dump()) == direct


def test_the_rest_of_a_result_is_bounded() -> None:
    """Library names, warnings, error messages and tracebacks are bounded too."""
    tech = Technology(
        name="n" * 5000,
        version="v" * 5000,
        detection=DetectionMethod.URI,
        source_url="https://example.com/a.js",
        advisories=("a" * 5000,),
    )
    error = CheckError(check_id="x", message="m" * 50_000, traceback="t" * 100_000)
    result = make_result(
        make_finding(), technologies=(tech,), errors=[error], warnings=["w" * 50_000]
    )
    (tech,) = result.technologies
    assert tech.name.endswith(TRUNCATION_MARKER) and len(tech.name) < 2 * NAME_MAX_CHARS
    assert tech.advisories[0].endswith(TRUNCATION_MARKER)
    assert result.errors[0].message == "m" * TEXT_MAX_CHARS + TRUNCATION_MARKER
    assert len(result.errors[0].traceback) == URL_MAX_CHARS + len(TRUNCATION_MARKER)
    assert result.warnings[0] == "w" * TEXT_MAX_CHARS + TRUNCATION_MARKER


def test_a_report_with_cut_fields_reloads_unchanged(tmp_path: Path) -> None:
    """The bound is applied once: the JSON report stays the exact inverse of ``load_result``."""
    finding = make_finding().model_copy(update={"title": "t" * 50_000})
    result = ScanResult.model_validate(make_result(finding).model_dump())
    assert load_result(_write(tmp_path, result)) == result


# ---------------------------------------------------------------------------
# Schema version
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("version", ["99", 99.0, "1", True])
def test_a_schema_version_that_is_not_an_integer_is_refused(version: object) -> None:
    """A string or a float cannot slip past the newer-schema check and be coerced afterwards."""
    with pytest.raises(ValidationError, match="schema_version"):
        ScanResult.model_validate_json(json.dumps(_document(schema_version=version)))


# ---------------------------------------------------------------------------
# Severity counts
# ---------------------------------------------------------------------------


def test_counts_are_recomputed_from_the_findings(tmp_path: Path) -> None:
    """A file whose counts claim a clean scan over a real finding shows the finding's count."""
    document = _document()
    metadata = document["metadata"]
    assert isinstance(metadata, dict)
    metadata["counts"] = {level.name: 0 for level in Severity}
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(document), "utf-8")

    result = load_result(path)

    assert result.metadata.counts[Severity.MEDIUM.name] == 1
    assert "| MEDIUM | 1 |" in get_reporter("md").render(result)


def test_matching_counts_are_kept_as_they_are() -> None:
    result = make_result(make_finding(severity=Severity.HIGH))
    assert ScanResult.model_validate(result.model_dump()) == result
