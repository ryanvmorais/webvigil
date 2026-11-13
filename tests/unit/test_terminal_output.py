"""
What the scanned site sent, on its way to a terminal: Rich markup and control characters.

A finding's title and location, a scan warning and a report's evidence quote the site (a cookie
name, a header value, a form field name, a body). The terminal summary must print them as text,
never as Rich markup, and every output that can reach a terminal (the summary, an error line,
the Markdown, HTML and JSON reports printed to stdout) must show a control character instead of
sending it. The summary is rendered into a :class:`~rich.console.Console` on a ``StringIO`` with
no colour, so the only escape bytes in the output would be the ones the site sent; the reporters
are pure functions of a canned :class:`ScanResult`. Nothing touches the network.
"""

from __future__ import annotations

import io
import re
from pathlib import Path

import pytest
from rich.console import Console

from tests.support import make_finding, make_result
from webvigil.cli import _render
from webvigil.core.findings import EvidenceItem, Finding, Location
from webvigil.core.result import ScanResult
from webvigil.core.text import show_controls
from webvigil.reporting import get_reporter, load_result

# A control character a terminal acts on: C0 except tab and line feed, DEL, the C1 range.
_RAW_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_ESC = "\x1b"
_CSI = "\x9b"


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


@pytest.fixture
def console(monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
    """
    Args:
        monkeypatch (pytest.MonkeyPatch): Swaps the module console.

    Returns:
        io.StringIO: What the terminal output module prints, with no colour codes of its own.
    """
    buffer = io.StringIO()
    monkeypatch.setattr(
        _render, "_console", Console(file=buffer, color_system=None, width=500, soft_wrap=True)
    )
    return buffer


def _finding(*, title: str, cookie: str, evidence: str = "body") -> Finding:
    """
    Args:
        title (str): The finding title.
        cookie (str): The cookie name of the location.
        evidence (str): The content of the one evidence item.

    Returns:
        Finding: A finding whose title, location and evidence carry the given text.
    """
    return make_finding().model_copy(
        update={
            "title": title,
            "location": Location(url="https://example.com/", cookie=cookie),
            "evidence": (EvidenceItem.of("Set-Cookie", evidence),),
        }
    )


# ---------------------------------------------------------------------------
# show_controls
# ---------------------------------------------------------------------------


def test_show_controls_writes_c0_del_and_c1_as_visible_escapes() -> None:
    assert show_controls(f"a{_ESC}b\x7fc{_CSI}d\x00e") == "a\\x1bb\\x7fc\\x9bd\\x00e"


def test_show_controls_keeps_layout_and_normalises_crlf() -> None:
    """Tab and line feed stay; CRLF reads as LF; a lone carriage return is shown."""
    assert show_controls("a\tb\r\nc\rd") == "a\tb\nc\\x0dd"


def test_show_controls_on_one_line_escapes_tab_and_line_feed_too() -> None:
    assert show_controls("a\tb\nc\r\nd", one_line=True) == "a\\x09b\\x0ac\\x0d\\x0ad"


# ---------------------------------------------------------------------------
# The terminal summary
# ---------------------------------------------------------------------------


def test_summary_prints_markup_from_a_finding_and_a_warning_as_text(
    console: io.StringIO,
) -> None:
    result = make_result(
        _finding(title="Title [bold]styled[/bold]", cookie="sid[italic]x[/italic]"),
        warnings=["note [link=https://example.org]here[/link]"],
    )
    _render.summary(result)
    out = console.getvalue()
    assert "Title [bold]styled[/bold]" in out
    assert "sid[italic]x[/italic]" in out
    assert "note [link=https://example.org]here[/link]" in out


@pytest.mark.parametrize("text", ["[/]", "[/bold]", "a [/x] b"])
def test_summary_completes_on_a_closing_tag_with_no_opening(
    console: io.StringIO, text: str
) -> None:
    """A tag that closes nothing used to raise inside the summary, so no finding was shown."""
    result = make_result(_finding(title=text, cookie=text), warnings=[text])
    _render.summary(result)
    out = console.getvalue()
    assert out.count(text) == 3
    assert "MEDIUM" in out


def test_summary_shows_control_characters_instead_of_sending_them(
    console: io.StringIO,
) -> None:
    result = make_result(
        _finding(title=f"t{_ESC}1", cookie=f"c{_CSI}2\n3"),
        warnings=[f"w{_ESC}4"],
    )
    _render.summary(result)
    out = console.getvalue()
    assert not _RAW_CONTROL_RE.search(out)
    assert "t\\x1b1" in out
    assert "c\\x9b2\\x0a3" in out
    assert "w\\x1b4" in out


def test_banner_prints_the_authorization_note_as_text(console: io.StringIO) -> None:
    _render.banner(f"ticket [/] 42{_ESC}")
    assert "ticket [/] 42\\x1b" in console.getvalue()


def test_error_and_status_lines_show_control_characters(console: io.StringIO) -> None:
    _render.error(f"bad{_ESC}value")
    _render.status(f"ok{_CSI}done")
    out = console.getvalue()
    assert not _RAW_CONTROL_RE.search(out)
    assert "bad\\x1bvalue" in out
    assert "ok\\x9bdone" in out


# ---------------------------------------------------------------------------
# Reports printed to stdout
# ---------------------------------------------------------------------------


def _hostile_result() -> ScanResult:
    """
    Returns:
        ScanResult: One finding whose title, location and evidence carry control characters.
    """
    return make_result(
        _finding(
            title=f"title{_CSI}x",
            cookie=f"sid{_ESC}y",
            evidence=f"line one\r\nline{_ESC}two\rover{_CSI}three\x7f",
        )
    )


@pytest.mark.parametrize("fmt", ["md", "html", "json", "sarif"])
def test_no_report_carries_a_raw_control_character(fmt: str) -> None:
    rendered = get_reporter(fmt).render(_hostile_result())
    assert not _RAW_CONTROL_RE.search(rendered)


@pytest.mark.parametrize("fmt", ["md", "html"])
def test_text_reports_show_the_evidence_controls_visibly(fmt: str) -> None:
    rendered = get_reporter(fmt).render(_hostile_result())
    assert "line one\nline\\x1btwo\\x0dover\\x9bthree\\x7f" in rendered


def test_json_report_escapes_c1_and_still_reloads_the_same_result(tmp_path: Path) -> None:
    r"""The ``\u00XX`` escape is the same string to a JSON parser: the round trip holds."""
    result = _hostile_result()
    rendered = get_reporter("json").render(result)
    assert "\\u009b" in rendered
    path = tmp_path / "scan.json"
    path.write_text(rendered, "utf-8")
    assert load_result(path) == result
