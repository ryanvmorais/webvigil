"""
Markdown report escaping — issue #172.

Pure rendering: a canned :class:`ScanResult` goes in, a string comes out; nothing is mocked and
nothing touches the network or the disk. The reference renderer is ``markdown-it`` (a CommonMark
parser that ``rich`` already brings in): each test parses the report and asserts on the token
stream, so "a title cannot start a heading" means the parser sees no extra heading, not that a
string lacks a character. The values are hostile on purpose (a fence, raw HTML, a link, a line
break) and stand for what a scanned site can put in a path, a parameter name, a cookie name or a
response body.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

import pytest
from markdown_it import MarkdownIt
from markdown_it.token import Token

from tests.support import make_finding, make_result
from webvigil.core.findings import EvidenceItem, Finding, Severity
from webvigil.core.result import CheckError, ScanResult
from webvigil.core.technology import DetectionMethod, Technology
from webvigil.reporting import get_reporter

_PARSER = MarkdownIt("commonmark").enable("table")

# What our own template emits as raw HTML: the evidence disclosure and nothing else.
_ALLOWED_HTML = re.compile(r"^(?:<details><summary>[^<>]*</summary>|</details>)$")


def _render(result: ScanResult) -> str:
    """
    Args:
        result (ScanResult): The result to render.

    Returns:
        str: The Markdown report.
    """
    return get_reporter("md").render(result)


def _walk(tokens: list[Token]) -> Iterator[Token]:
    """
    Args:
        tokens (list[Token]): A token list from the parser.

    Yields:
        Token: Every token, depth first, the children of inline tokens included.
    """
    for token in tokens:
        yield token
        if token.children:
            yield from _walk(token.children)


def _tokens(md: str) -> list[Token]:
    """
    Args:
        md (str): A Markdown document.

    Returns:
        list[Token]: Every token ``markdown-it`` finds in it, flattened.
    """
    return list(_walk(_PARSER.parse(md)))


def _heading_texts(md: str, tag: str) -> list[str]:
    """
    Args:
        md (str): A Markdown document.
        tag (str): The heading tag, ``"h1"`` / ``"h2"``.

    Returns:
        list[str]: The visible text of each heading of that level.
    """
    top = _PARSER.parse(md)
    texts = []
    for index, token in enumerate(top):
        if token.type == "heading_open" and token.tag == tag:
            inline = top[index + 1]
            texts.append(
                "".join(
                    child.content
                    for child in inline.children or []
                    if child.type.startswith("text") or child.type == "code_inline"
                )
            )
    return texts


def _hostile(**update: object) -> Finding:
    """
    Args:
        **update (object): Fields of the finding to replace.

    Returns:
        Finding: A finding whose fields are overridden by ``update``.
    """
    return make_finding(check_id="injection.xss.reflected").model_copy(update=update)


# ---------------------------------------------------------------------------
# Hostile values stay plain text
# ---------------------------------------------------------------------------


def test_hostile_values_are_rendered_as_plain_text() -> None:
    """No heading, link, image or raw HTML appears that the template did not write."""
    title = "a <img src=x onerror=alert(1)> [click](javascript:alert(1))\n## injected"
    finding = _hostile(
        title=title,
        description="see ![x](http://evil.test/p.png) and <script>alert(1)</script>",
        remediation="<a href=javascript:alert(1)>fix</a> [here](javascript:alert(1))",
        evidence=[
            EvidenceItem.of("</summary><img src=x onerror=1>", "```\n</details>\n<b>x</b>\n````")
        ],
        references=("<javascript:alert(1)>", "[r](javascript:alert(1))"),
    )
    md = _render(make_result(finding))
    tokens = _tokens(md)

    assert _heading_texts(md, "h2") == [
        "[MEDIUM] a <img src=x onerror=alert(1)> [click](javascript:alert(1)) ## injected"
    ]
    assert not [t for t in tokens if t.type in ("link_open", "image", "html_inline")]
    for html_block in (t for t in tokens if t.type == "html_block"):
        assert _ALLOWED_HTML.match(html_block.content.strip()), html_block.content
    (fence,) = (t for t in tokens if t.type == "fence")
    assert fence.content == "```\n</details>\n<b>x</b>\n````\n"


def test_the_summary_label_is_html_escaped() -> None:
    """The ``<summary>`` line sits in a raw HTML block, so its label gets the HTML escape."""
    finding = _hostile(evidence=[EvidenceItem.of("</summary><img src=x onerror=1>", "x")])
    md = _render(make_result(finding))
    assert (
        "<details><summary>&lt;/summary&gt;&lt;img src=x onerror=1&gt;</summary>" in md.splitlines()
    )


@pytest.mark.parametrize("run", [3, 4, 5, 12])
def test_evidence_cannot_close_its_own_fence(run: int) -> None:
    """The fence is longer than any backtick run in the content, so one block holds it all."""
    content = f"before\n{'`' * run}\nafter <b>not html</b>\n~~~"
    finding = _hostile(evidence=[EvidenceItem.of("body", content)])
    tokens = _tokens(_render(make_result(finding)))
    (fence,) = (t for t in tokens if t.type == "fence")
    assert fence.content == content + "\n"
    assert not [t for t in tokens if t.type == "html_inline"]


def test_a_line_break_in_a_title_does_not_split_the_heading() -> None:
    """CR, LF and the Unicode line separators collapse to a space; the finding stays one h2."""
    finding = _hostile(title="one\r\n## two\u2028### three\x00four")
    md = _render(make_result(finding))
    assert _heading_texts(md, "h2") == ["[MEDIUM] one ## two ### three four"]


def test_a_description_cannot_open_a_block() -> None:
    """Lines that look like a heading, a quote, a list, a rule or a fence stay paragraph text."""
    description = "# not a heading\n- not a list\n1. not a list\n> not a quote\n---\n```\ncode?"
    md = _render(make_result(_hostile(description=description, remediation="- no\n# no")))
    tokens = _tokens(md)
    kinds = {t.type for t in tokens}
    assert not kinds & {"ordered_list_open", "blockquote_open", "hr", "fence"}
    # Only what the template writes: the title, the finding heading, and its three lists
    # (report metadata, finding metadata, references).
    assert sum(t.type == "heading_open" for t in tokens) == 2
    assert sum(t.type == "bullet_list_open" for t in tokens) == 3
    assert _heading_texts(md, "h2") == ["[MEDIUM] injection.xss.reflected finding"]


def test_a_table_cell_survives_a_pipe_in_a_library_name() -> None:
    """A ``|`` in a name or version stays inside its cell: the row keeps four columns."""
    tech = Technology(
        name="a|b",
        version="1|2",
        detection=DetectionMethod.URI,
        source_url="https://example.com/a.js",
        vulnerable=True,
        advisories=("CVE-1|x",),
    )
    md = _render(make_result(make_finding(), technologies=(tech,)))
    section = md.split("## Detected technologies")[1].split("\n## ")[0]
    top = _PARSER.parse(section)
    assert sum(t.type == "th_open" for t in top) == 4
    cells = [
        "".join(c.content for c in top[i + 1].children or [] if c.type.startswith("text"))
        for i, t in enumerate(top)
        if t.type == "td_open"
    ]
    assert cells == ["a|b", "1|2", DetectionMethod.URI.value, "Vulnerable (CVE-1|x)"]


def test_check_error_text_is_plain() -> None:
    """An error message, which can echo the target, cannot break out of its list item."""
    error = CheckError(check_id="x`y", message="boom <b>\n## h\n[l](javascript:1)", traceback="")
    md = _render(make_result(make_finding(), errors=[error]))
    tokens = _tokens(md)
    assert _heading_texts(md, "h2")[-1] == "Check errors"
    assert sum(t.type == "list_item_open" for t in tokens) >= 1
    assert not [t for t in tokens if t.type in ("link_open", "html_inline")]


def test_a_location_key_cannot_end_its_code_span() -> None:
    """A parameter name with backticks is wrapped in a longer delimiter."""
    finding = make_finding(url="https://example.com/p", param="q`<script>`z")
    tokens = _tokens(_render(make_result(finding)))
    assert "q`<script>`z" in [t.content for t in tokens if t.type == "code_inline"]
    assert not [t for t in tokens if t.type == "html_inline"]


# ---------------------------------------------------------------------------
# An ordinary report is unchanged
# ---------------------------------------------------------------------------


def test_an_ordinary_finding_is_written_as_before() -> None:
    """Plain titles, URLs, and the check authors' own code spans come out as they went in."""
    finding = make_finding(url="https://example.com/_next/a_b?x=1&y=2").model_copy(
        update={
            "title": "Missing Content-Security-Policy header",
            "description": "Add `integrity` to every `<script>` (see RFC 9110).",
            "remediation": "Set the header; do not use 'unsafe-inline'.",
        }
    )
    lines = _render(make_result(finding)).splitlines()
    assert "## [MEDIUM] Missing Content-Security-Policy header" in lines
    assert "- Check: `http.headers.csp` · Confidence: HIGH" in lines
    assert "- Location: https://example.com/_next/a_b?x=1&y=2 (`Content-Security-Policy`)" in lines
    assert "Add `integrity` to every `<script>` (see RFC 9110)." in lines
    assert "**Remediation:** Set the header; do not use 'unsafe-inline'." in lines
    assert "- https://owasp.org/www-project-secure-headers/" in lines


def test_the_check_authors_code_spans_are_kept_as_code() -> None:
    """A paired backtick run is still a code span; an unpaired one is escaped to a literal."""
    finding = _hostile(description="Use `integrity` and `<script>`; never a lone ` here.")
    tokens = _tokens(_render(make_result(finding)))
    spans = [t.content for t in tokens if t.type == "code_inline"]
    assert "integrity" in spans and "<script>" in spans
    paragraph_text = "".join(t.content for t in tokens if t.type.startswith("text"))
    assert "never a lone ` here." in paragraph_text


def test_severity_and_counts_are_untouched() -> None:
    """The summary table and the finding header carry the severity name as before."""
    result = make_result(make_finding(severity=Severity.HIGH))
    md = _render(result)
    assert "| HIGH | 1 |" in md
    assert "## [HIGH] http.headers.csp finding" in md
