"""
HTML reporter: one self-contained file, no external requests (RF-23).
"""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, select_autoescape

from webvigil.core.findings import Severity
from webvigil.core.result import ScanResult
from webvigil.core.urls import is_http_url
from webvigil.reporting._ordering import sort_findings

_env = Environment(
    loader=PackageLoader("webvigil.reporting", "templates"),
    autoescape=select_autoescape(["html", "html.j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
# ``r is http_url`` in the template: a reference becomes a link only when it is an http(s) URL
# (issue #161). Autoescaping alone does not stop a ``javascript:`` scheme from being a link.
_env.tests["http_url"] = is_http_url


class HtmlReporter:
    """Renders a scan result through the bundled Jinja2 template into a standalone HTML page."""

    fmt = "html"

    def render(self, result: ScanResult) -> str:
        """
        Args:
            result (ScanResult): The scan result.

        Returns:
            str: A complete, self-contained HTML document — no external CSS,
                JS, or images.
        """
        template = _env.get_template("report.html.j2")
        return template.render(
            meta=result.metadata,
            findings=sort_findings(result.findings),
            technologies=result.technologies,
            errors=result.errors,
            warnings=result.warnings,
            severities=list(reversed(list(Severity))),
        )
