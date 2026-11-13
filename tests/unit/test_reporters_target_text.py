"""
What the scanned site sent, as the Markdown, SARIF, HTML and JSON reports write it.

Pure rendering: a canned :class:`ScanResult` goes in, a string comes out; nothing is mocked and
nothing touches the network or the disk. The values stand for what a site can put in a path, a
parameter name, a library name or a response body: a pipe inside a code span (a table cell), a
mention, an issue reference and a bare URL (GitHub links them when a report is pasted there), a
bracketed link (a SARIF viewer renders it), a URL no strict URI parser accepts, and the
bidirectional and zero-width characters that make a text read differently from what it holds.
"""

from __future__ import annotations

import json
from typing import Any

from markdown_it import MarkdownIt

from tests.support import make_finding, make_result
from webvigil.core.findings import EvidenceItem, Finding
from webvigil.core.result import ScanResult
from webvigil.core.technology import DetectionMethod, Technology
from webvigil.reporting import get_reporter

_PARSER = MarkdownIt("commonmark").enable("table")
_ZERO_WIDTH_SPACE = chr(0x200B)
_RIGHT_TO_LEFT_OVERRIDE = chr(0x202E)
_BYTE_ORDER_MARK = chr(0xFEFF)


def _render(fmt: str, result: ScanResult) -> str:
    """
    Args:
        fmt (str): The report format.
        result (ScanResult): The result to render.

    Returns:
        str: The report.
    """
    return get_reporter(fmt).render(result)


def _with(**update: object) -> Finding:
    """
    Args:
        **update (object): Fields of the finding to replace.

    Returns:
        Finding: The default finding with ``update`` applied.
    """
    return make_finding().model_copy(update=update)


def _sarif(*findings: Finding) -> dict[str, Any]:
    """
    Args:
        *findings (Finding): The findings of the scan.

    Returns:
        dict[str, Any]: The single SARIF run.
    """
    document = json.loads(_render("sarif", make_result(*findings)))
    run: dict[str, Any] = document["runs"][0]
    return run


# ---------------------------------------------------------------------------
# Markdown: table cells
# ---------------------------------------------------------------------------


def test_a_pipe_inside_backticks_stays_in_its_table_cell() -> None:
    """GFM splits a row at a ``|`` even inside a code span, so a cell holds no code span."""
    tech = Technology(
        name="a`|`b",
        version="1`|`2",
        detection=DetectionMethod.URI,
        source_url="https://example.com/a.js",
        vulnerable=True,
        advisories=("x`|`y",),
    )
    md = _render("md", make_result(make_finding(), technologies=(tech,)))
    section = md.split("## Detected technologies")[1].split("\n## ")[0]
    top = _PARSER.parse(section)
    assert sum(t.type == "th_open" for t in top) == 4
    assert sum(t.type == "td_open" for t in top) == 4
    assert not [c for t in top for c in t.children or [] if c.type == "code_inline"]
    cells = [
        "".join(c.content for c in top[i + 1].children or [] if c.type.startswith("text"))
        for i, t in enumerate(top)
        if t.type == "td_open"
    ]
    assert cells == ["a`|`b", "1`|`2", DetectionMethod.URI.value, "Vulnerable (x`|`y)"]


# ---------------------------------------------------------------------------
# Markdown: mentions, references and autolinks
# ---------------------------------------------------------------------------


def test_mentions_issue_references_and_bare_urls_are_broken() -> None:
    """GitHub finds no ``@name``, ``#12``, ``www.`` or ``scheme://``; the text reads the same."""
    title = "ping @octocat about #12 via www.evil.test or https://evil.test/x"
    md = _render("md", make_result(_with(title=title, references=())))
    for trigger in ("@octocat", "#12", "www.evil", "https://evil"):
        assert trigger not in md
    (heading,) = (line for line in md.splitlines() if line.startswith("## "))
    (inline,) = (t for t in _PARSER.parse(heading) if t.type == "inline")
    shown = "".join(c.content for c in inline.children or [] if c.type.startswith("text"))
    assert shown.replace(_ZERO_WIDTH_SPACE, "") == f"[MEDIUM] {title}"


def test_an_evidence_label_breaks_a_mention_too() -> None:
    """The ``<summary>`` line is raw HTML, where GitHub still links a mention."""
    md = _render("md", make_result(_with(evidence=[EvidenceItem.of("cookie of @octocat", "x")])))
    assert "<details><summary>cookie of @&#8203;octocat</summary>" in md.splitlines()


def test_a_code_span_is_left_as_written() -> None:
    """GitHub links nothing inside code, so a check author's code span keeps its text."""
    md = _render("md", make_result(_with(description="Annotate with `@Valid` and `#1`.")))
    spans = [
        c.content for t in _PARSER.parse(md) for c in t.children or [] if c.type == "code_inline"
    ]
    assert "@Valid" in spans and "#1" in spans


def test_only_an_http_reference_becomes_a_link() -> None:
    """The rule of the HTML report: an ``http(s)`` URL is an autolink, anything else is text."""
    references = (
        "https://example.org/ref",
        "javascript:alert(1)",
        "https://example.org/<x>",
        f"https://example.org/{_RIGHT_TO_LEFT_OVERRIDE}fdp.exe",
    )
    md = _render("md", make_result(_with(references=references)))
    links = [
        dict(c.attrs)["href"]
        for t in _PARSER.parse(md)
        for c in t.children or []
        if c.type == "link_open"
    ]
    assert links == ["https://example.org/ref"]


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


def test_a_bracketed_link_in_a_sarif_message_is_escaped() -> None:
    """SARIF 2.1.0 section 3.11.6: brackets and backslashes are escaped in a plain-text message."""
    finding = _with(title="[click](https://evil.test)", description="a\\b")
    (result,) = _sarif(finding)["results"]
    assert result["message"]["text"] == "\\[click\\](https://evil.test). a\\\\b"


def test_a_rule_is_described_by_its_check_id_not_by_a_finding_title() -> None:
    """The first finding's title, which can carry the site's text, does not name the rule."""
    run = _sarif(_with(title="Missing header on /@evil"))
    (rule,) = run["tool"]["driver"]["rules"]
    assert rule["shortDescription"] == {"text": "WebVigil check http.headers.csp"}


def test_help_uri_is_the_first_http_reference() -> None:
    """A ``javascript:`` reference is skipped; a rule with no ``http(s)`` one has no help link."""
    linked = _sarif(_with(references=("javascript:alert(1)", "https://example.org/ref")))
    (rule,) = linked["tool"]["driver"]["rules"]
    assert rule["helpUri"] == "https://example.org/ref"
    unlinked = _sarif(_with(references=("javascript:alert(1)",)))
    (rule,) = unlinked["tool"]["driver"]["rules"]
    assert "helpUri" not in rule


def test_a_location_is_percent_encoded_into_a_valid_uri() -> None:
    """A space, a non-ASCII letter or an angle bracket is encoded; an existing escape is kept."""
    finding = make_finding(url="https://example.com/a b/é?q=<x>&r=%41", param="q")
    (result,) = _sarif(finding)["results"]
    (location,) = result["locations"]
    uri = location["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "https://example.com/a%20b/%C3%A9?q=%3Cx%3E&r=%41"
    (logical,) = location["logicalLocations"]
    assert logical["fullyQualifiedName"] == f"GET {uri}#q"


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------


def test_the_html_report_carries_its_own_content_security_policy() -> None:
    """Opened from a file there is no header, so the page declares the policy before any style."""
    html = _render("html", make_result(make_finding()))
    head = html.split("</head>")[0]
    policy = (
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
    )
    assert policy in head
    assert head.index(policy) < head.index("<style>")
    assert "<script" not in html


# ---------------------------------------------------------------------------
# Bidirectional and invisible characters
# ---------------------------------------------------------------------------


def test_text_reports_show_bidirectional_and_invisible_characters() -> None:
    """Markdown and HTML write each one as a visible escape, in the title and the evidence."""
    finding = _with(
        title=f"admin{_ZERO_WIDTH_SPACE}user {_RIGHT_TO_LEFT_OVERRIDE}fdp.exe",
        evidence=[EvidenceItem.of("body", f"{_BYTE_ORDER_MARK}<p>x</p>")],
    )
    for fmt in ("md", "html"):
        report = _render(fmt, make_result(finding))
        for char in (_ZERO_WIDTH_SPACE, _RIGHT_TO_LEFT_OVERRIDE, _BYTE_ORDER_MARK):
            assert char not in report, fmt
        assert "admin\\u200buser \\u202efdp.exe" in report, fmt
        assert "\\ufeff" in report, fmt


def test_json_escapes_bidirectional_characters_and_keeps_the_value() -> None:
    """An escaped character is the same string to a JSON parser."""
    title = f"a{_RIGHT_TO_LEFT_OVERRIDE}b{_ZERO_WIDTH_SPACE}c"
    report = _render("json", make_result(_with(title=title)))
    assert _RIGHT_TO_LEFT_OVERRIDE not in report and _ZERO_WIDTH_SPACE not in report
    assert json.loads(report)["findings"][0]["title"] == title
