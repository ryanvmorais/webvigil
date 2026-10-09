"""
Markdown reporter: a summary table plus a section per finding (RF-23).

A report is built from what the scanned site sent (titles with a path or a parameter name,
evidence, cookie names, library names), so every such value is written as plain text: the
Markdown and HTML metacharacters are escaped, a line break cannot start a new block, and the
evidence is fenced (and inline code delimited) with a run of backticks longer than any run in
the content, so it cannot close the block early. The HTML report gets the same guarantee from
Jinja's autoescaping; JSON and SARIF are data (issue #172).
"""

from __future__ import annotations

import html
import re

from webvigil.core.findings import Severity
from webvigil.core.result import ScanResult
from webvigil.reporting._ordering import sort_findings

# ---------------------------------------------------------------------------
# Escaping
# ---------------------------------------------------------------------------

# Line breaks and control characters: a value that must stay on one line (a heading, a table
# cell, a list item) cannot start a new block through one of them.
_BREAKS_RE = re.compile(r"[\r\n\x00-\x08\x0b-\x1f\x7f\u0085\u2028\u2029]+")
# Markdown that changes meaning anywhere in a line, and `<` for raw HTML. ``_`` is left alone on
# purpose: an intra-word one is never emphasis, and ``/_next/`` must stay a readable URL; the
# worst a stray one does is italicise.
_INLINE_RE = re.compile(r"[\\`*\[\]|<]")
# ``&`` only matters when it can complete a character reference (``&lt;``, ``&#60;``); a bare one
# (a query string) stays as it is.
_ENTITY_RE = re.compile(r"&(?=#?\w+;)")
# A line that opens a block when it starts with one of these: heading, quote, list, rule, fence.
_LINE_START_RE = re.compile(r"^[#>+=~-]")
_ORDERED_LIST_RE = re.compile(r"^(\d+)([.)])")
_BACKTICK_RUN_RE = re.compile(r"`+")


def _plain(value: str) -> str:
    """
    Args:
        value (str): Text outside any code span.

    Returns:
        str: ``value`` with the Markdown and HTML metacharacters escaped. The character
            references are escaped first, so the ``&`` of a ``&lt;`` written here is not.
    """
    value = _ENTITY_RE.sub("&amp;", value)
    return _INLINE_RE.sub(lambda m: "&lt;" if m.group() == "<" else "\\" + m.group(), value)


def _escape(value: str) -> str:
    """
    Args:
        value (str): Text that came from a check or from the scanned site.

    Returns:
        str: ``value`` with the metacharacters escaped, line breaks kept. A backtick run pairs
            with the next run of the same length, as in CommonMark, and what is between them
            stays a code span: the checks quote identifiers that way (`integrity`, `<script>`),
            and the HTML report shows them as written. Each span is written again with a
            delimiter longer than any run inside it, so it cannot end early; a run with no
            partner is escaped. Nothing outside a span is left unescaped, whatever pairing a
            renderer would choose.
    """
    runs = list(_BACKTICK_RUN_RE.finditer(value))
    partner: dict[int, int] = {}  # index of a run -> index of the next run of the same length
    last_seen: dict[int, int] = {}
    for index in range(len(runs) - 1, -1, -1):
        length = len(runs[index].group())
        if length in last_seen:
            partner[index] = last_seen[length]
        last_seen[length] = index
    parts: list[str] = []
    position = 0
    index = 0
    while index < len(runs):
        close = partner.get(index)
        if close is None or runs[index].start() < position:
            index += 1
            continue
        parts.append(_plain(value[position : runs[index].start()]))
        parts.append(_code(value[runs[index].end() : runs[close].start()]))
        position = runs[close].end()
        index = close + 1
    parts.append(_plain(value[position:]))
    return "".join(parts)


def _text(value: str) -> str:
    """
    Args:
        value (str): Text for a heading, a table cell or a list item.

    Returns:
        str: ``value`` as one line of plain text: breaks and control characters become a space
            and the metacharacters are escaped.
    """
    return _escape(_BREAKS_RE.sub(" ", value).strip())


def _block(value: str) -> str:
    """
    Args:
        value (str): A multi-line paragraph (a description, a remediation).

    Returns:
        str: ``value`` as plain text whose lines cannot open a heading, a quote, a list, a rule
            or a code block: each line is escaped, stripped of indentation and, when it starts
            like a block, led by a backslash.
    """
    lines = []
    for raw in value.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = _escape(_BREAKS_RE.sub(" ", raw).strip())
        line = _ORDERED_LIST_RE.sub(r"\1\\\2", line)
        if _LINE_START_RE.match(line):
            line = "\\" + line
        lines.append(line)
    return "\n".join(lines)


def _code(value: str) -> str:
    """
    Args:
        value (str): Text for an inline code span.

    Returns:
        str: A code span whose delimiter is longer than any backtick run in ``value``, so it
            cannot end the span early; padded when ``value`` starts or ends with a backtick.
    """
    value = _BREAKS_RE.sub(" ", value)
    longest = max((len(run) for run in _BACKTICK_RUN_RE.findall(value)), default=0)
    mark = "`" * (longest + 1)
    pad = " " if value.startswith("`") or value.endswith("`") else ""
    return f"{mark}{pad}{value}{pad}{mark}"


def _fence(content: str) -> list[str]:
    """
    Args:
        content (str): Evidence text.

    Returns:
        list[str]: The lines of a fenced code block, opened and closed by a run of backticks
            longer than any run in ``content`` (at least three).
    """
    longest = max((len(run) for run in _BACKTICK_RUN_RE.findall(content)), default=0)
    mark = "`" * max(3, longest + 1)
    return [mark, content, mark]


def _summary(label: str) -> str:
    """
    Args:
        label (str): An evidence label.

    Returns:
        str: ``label`` escaped for HTML, on one line. The ``<summary>`` line is a raw HTML
            block, where Markdown is not processed, so the HTML escape is the right one here.
    """
    return html.escape(_BREAKS_RE.sub(" ", label).strip(), quote=False)


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------


class MarkdownReporter:
    """Renders a scan result as Markdown: metadata, a severity table, per-finding sections."""

    fmt = "md"

    def render(self, result: ScanResult) -> str:
        """
        Args:
            result (ScanResult): The scan result.

        Returns:
            str: The Markdown report, ending in a single trailing newline.
        """
        meta = result.metadata
        lines: list[str] = [
            f"# WebVigil scan report — {_text(meta.target)}",
            "",
            f"- Mode: {_code(meta.mode.value)} · Scope: {_code(meta.scope.value)} · "
            f"Pages scanned: {meta.pages_scanned}",
            f"- Started: {meta.started_at.isoformat()} · Finished: {meta.finished_at.isoformat()}",
        ]
        if meta.authorized_by:
            lines.append(f"- Authorized by: {_text(meta.authorized_by)}")
        lines += ["", "| Severity | Count |", "| --- | --- |"]
        for severity in reversed(list(Severity)):
            lines.append(f"| {severity.name} | {meta.counts.get(severity.name, 0)} |")
        lines.append("")

        if result.technologies:
            lines += [
                "## Detected technologies",
                "",
                "| Library | Version | Detection | Status |",
                "| --- | --- | --- | --- |",
            ]
            for tech in result.technologies:
                status = "**Vulnerable**" if tech.vulnerable else "—"
                if tech.vulnerable and tech.advisories:
                    status += f" ({_text(', '.join(tech.advisories))})"
                version = _text(tech.version) if tech.version else "unknown"
                lines.append(
                    f"| {_text(tech.name)} | {version} | {tech.detection.value} | {status} |"
                )
            lines.append("")

        findings = sort_findings(result.findings)
        if not findings:
            lines += ["No findings.", ""]
        for finding in findings:
            lines += [
                f"## [{finding.severity.name}] {_text(finding.title)}",
                "",
                f"- Check: {_code(finding.check_id)} · Confidence: {finding.confidence.name}",
                f"- Location: {_text(finding.location.url)}"
                + (f" ({_code(finding.location.key)})" if finding.location.key else ""),
            ]
            if finding.cwe:
                lines.append(f"- CWE: {', '.join(f'CWE-{c}' for c in finding.cwe)}")
            lines += [
                "",
                _block(finding.description),
                "",
                f"**Remediation:** {_block(finding.remediation)}",
                "",
            ]
            for item in finding.evidence:
                lines += [
                    f"<details><summary>{_summary(item.label)}</summary>",
                    "",
                    *_fence(item.content),
                    "",
                    "</details>",
                    "",
                ]
            for reference in finding.references:
                lines.append(f"- {_text(reference)}")
            lines.append("")

        if result.errors:
            lines += ["## Check errors", ""]
            lines += [
                f"- {_code(error.check_id)}: {_text(error.message)}" for error in result.errors
            ]
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"
