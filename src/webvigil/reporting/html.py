"""HTML reporter: one self-contained file, no external requests (RF-23)."""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, select_autoescape

from webvigil.core.findings import Severity
from webvigil.core.result import ScanResult
from webvigil.reporting._ordering import sort_findings

_env = Environment(
    loader=PackageLoader("webvigil.reporting", "templates"),
    autoescape=select_autoescape(["html", "html.j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


class HtmlReporter:
    fmt = "html"

    def render(self, result: ScanResult) -> str:
        template = _env.get_template("report.html.j2")
        return template.render(
            meta=result.metadata,
            findings=sort_findings(result.findings),
            technologies=result.technologies,
            errors=result.errors,
            warnings=result.warnings,
            severities=list(reversed(list(Severity))),
        )
