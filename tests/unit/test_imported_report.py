"""
A report read back from a file: the size of the file, the size of each field, the schema version
and the severity counts.

``webvigil report`` reloads a JSON report that someone else may have written, so nothing in it
is taken on trust. The tests write files to ``tmp_path``; most lower ``MAX_REPORT_BYTES`` with
``monkeypatch``, and one writes the real 64 MiB as spaces after a small report, which parse at
almost no cost. The field tests build the models directly, since the same bound applies when a
check builds a finding and when a file is read.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
from collections.abc import Callable
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
_MIB = 1024 * 1024


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


class _ReadSpy:
    """A report file that records the size of every read asked of it."""

    def __init__(self, data: bytes) -> None:
        """
        Args:
            data (bytes): What the file holds.
        """
        self._file = io.BytesIO(data)
        self.asked: list[int] = []

    def __enter__(self) -> _ReadSpy:
        """Open the file."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close the file."""

    def read(self, size: int = -1) -> bytes:
        """
        Args:
            size (int): The most bytes to read. Defaults to ``-1`` (all of them).

        Returns:
            bytes: The next bytes of the file.
        """
        self.asked.append(size)
        return self._file.read(size)


def test_the_report_is_read_one_mebibyte_at_a_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """Memory follows what the file holds: no read asks for the whole limit (spec 025, RF-08)."""
    document = get_reporter("json").render(make_result(make_finding())).encode()
    spy = _ReadSpy(document + b" " * (3 * _MIB + 5))

    class _Opener:
        def __init__(self, _path: object) -> None: ...

        def open(self, _mode: str) -> _ReadSpy:
            return spy

    monkeypatch.setattr(reporting, "Path", _Opener)

    assert len(load_result("scan.json").findings) == 1
    assert max(spy.asked) == _MIB
    # positive control: the file took several reads, the last of them finding its end
    assert len(spy.asked) == 5


def test_a_report_over_the_limit_is_read_one_byte_past_it_and_no_further(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The last read asks only for what is left up to one byte past the limit."""
    limit = 3 * _MIB + 10
    spy = _ReadSpy(b" " * (5 * _MIB))
    monkeypatch.setattr(reporting, "MAX_REPORT_BYTES", limit)

    with pytest.raises(ValueError, match="larger than"):
        reporting._read_bounded(spy)  # type: ignore[arg-type]

    assert spy.asked == [_MIB, _MIB, _MIB, 11]


def _padded(tmp_path: Path, size: int) -> Path:
    """
    Args:
        tmp_path (Path): The test's temporary directory.
        size (int): The size of the file to write.

    Returns:
        Path: A valid report of one finding, padded with spaces to ``size`` bytes.
    """
    document = get_reporter("json").render(make_result(make_finding())).encode()
    path = tmp_path / "padded.json"
    path.write_bytes(document + b" " * (size - len(document)))
    return path


def test_a_report_of_64_mib_is_read_and_one_byte_more_is_refused(tmp_path: Path) -> None:
    """The real limit, not a lowered one: JSON allows the spaces, so only the size decides."""
    assert reporting.MAX_REPORT_BYTES == 64 * _MIB
    path = _padded(tmp_path, 64 * _MIB)
    assert len(load_result(path).findings) == 1
    path = _padded(tmp_path, 64 * _MIB + 1)
    with pytest.raises(ValueError, match=r"larger than 64 MiB"):
        load_result(path)
    path.unlink()


# What reading back measures, in a child process: the peak resident size above the one before.
_PEAK_SCRIPT = """
import resource, sys
from webvigil.reporting import load_result
before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
load_result(sys.argv[1])
after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print((after - before) * (1 if sys.platform == "darwin" else 1024))
"""


def _dense_document(size: int) -> bytes:
    """
    Args:
        size (int): About how large the document is.

    Returns:
        bytes: A report of many findings with short values, the densest kind of file.
    """
    one = json.loads(get_reporter("json").render(make_result(make_finding())))
    finding = one["findings"][0]
    count = size // len(json.dumps(finding))
    return json.dumps({**one, "findings": [finding] * count}).encode()


def _large_values_document(size: int) -> bytes:
    """
    Args:
        size (int): About how large the document is.

    Returns:
        bytes: A report of findings with 4 KiB of evidence each.
    """
    finding = make_finding().model_copy(
        update={"evidence": (EvidenceItem(label="body", content="x" * 4096),)}
    )
    one = json.loads(get_reporter("json").render(make_result(finding)))
    count = size // len(json.dumps(one["findings"][0]))
    return json.dumps({**one, "findings": one["findings"] * count}).encode()


@pytest.mark.skipif(sys.platform == "win32", reason="the peak resident size is a POSIX measure")
@pytest.mark.parametrize(
    ("build", "ratio"), [(_dense_document, 20), (_large_values_document, 5)], ids=["dense", "large"]
)
def test_reading_a_report_back_takes_memory_in_proportion_to_its_size(
    tmp_path: Path, build: Callable[[int], bytes], ratio: int
) -> None:
    """Measured on 8 MiB, the worst cases of the design stay under their ratio (spec 025, RF-08)."""
    path = tmp_path / "report.json"
    path.write_bytes(build(8 * _MIB))
    size = path.stat().st_size

    child = subprocess.run(
        [sys.executable, "-c", _PEAK_SCRIPT, str(path)],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    peak = int(child.stdout)

    # positive control: the measure saw the file come in
    assert peak >= size
    assert peak < ratio * size, f"{peak / size:.1f}x"


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
        source_url="https://example.com/" + "s" * 100_000,
        advisories=("a" * 5000,),
    )
    error = CheckError(check_id="x", message="m" * 50_000, traceback="t" * 100_000)
    result = make_result(
        make_finding(), technologies=(tech,), errors=[error], warnings=["w" * 50_000]
    )
    (tech,) = result.technologies
    assert tech.name == "n" * NAME_MAX_CHARS + TRUNCATION_MARKER
    assert tech.version == "v" * NAME_MAX_CHARS + TRUNCATION_MARKER
    assert len(tech.source_url) == URL_MAX_CHARS + len(TRUNCATION_MARKER)
    assert tech.advisories[0] == "a" * NAME_MAX_CHARS + TRUNCATION_MARKER
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
