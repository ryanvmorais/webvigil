"""Markdown reporter: a summary table plus a section per finding (RF-23)."""

from __future__ import annotations

from webvigil.core.findings import Severity
from webvigil.core.result import ScanResult
from webvigil.reporting._ordering import sort_findings


class MarkdownReporter:
    fmt = "md"

    def render(self, result: ScanResult) -> str:
        meta = result.metadata
        lines: list[str] = [
            f"# WebVigil scan report — {meta.target}",
            "",
            f"- Mode: `{meta.mode.value}` · Scope: `{meta.scope.value}` · "
            f"Pages scanned: {meta.pages_scanned}",
            f"- Started: {meta.started_at.isoformat()} · Finished: {meta.finished_at.isoformat()}",
        ]
        if meta.authorized_by:
            lines.append(f"- Authorized by: {meta.authorized_by}")
        lines += ["", "| Severity | Count |", "| --- | --- |"]
        for severity in reversed(list(Severity)):
            lines.append(f"| {severity.name} | {meta.counts.get(severity.name, 0)} |")
        lines.append("")

        findings = sort_findings(result.findings)
        if not findings:
            lines += ["No findings.", ""]
        for finding in findings:
            lines += [
                f"## [{finding.severity.name}] {finding.title}",
                "",
                f"- Check: `{finding.check_id}` · Confidence: {finding.confidence.name}",
                f"- Location: {finding.location.url}"
                + (f" (`{finding.location.key}`)" if finding.location.key else ""),
            ]
            if finding.cwe:
                lines.append(f"- CWE: {', '.join(f'CWE-{c}' for c in finding.cwe)}")
            lines += ["", finding.description, "", f"**Remediation:** {finding.remediation}", ""]
            for item in finding.evidence:
                lines += [
                    f"<details><summary>{item.label}</summary>",
                    "",
                    "```",
                    item.content,
                    "```",
                    "",
                    "</details>",
                    "",
                ]
            for reference in finding.references:
                lines.append(f"- {reference}")
            lines.append("")

        if result.errors:
            lines += ["## Check errors", ""]
            lines += [f"- `{error.check_id}`: {error.message}" for error in result.errors]
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"
