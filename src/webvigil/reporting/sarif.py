"""
SARIF 2.1.0 reporter (RF-22, ADR-7).

The document is built by hand — a small, fixed slice of SARIF. A schema test
guards the mapping.

A finding's title, description and location carry what the scanned site sent, and a SARIF viewer
renders ``[text](target)`` inside a message as a link. So the brackets in a message are escaped,
a rule is described by its fixed check id (not by the title of whichever finding came first),
``helpUri`` is only an ``http(s)`` URL, and a location is percent-encoded into a valid URI.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote

from webvigil.core.findings import Finding, Severity
from webvigil.core.result import ScanResult
from webvigil.core.urls import is_http_url

_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
_INFORMATION_URI = "https://github.com/ryanvmorais/webvigil"
# SARIF 2.1.0 section 3.11.6: a literal bracket in a plain-text message is escaped with a
# backslash, and so is a literal backslash, so ``[text](1)`` from the site stays text.
_MESSAGE_ESCAPE_RE = re.compile(r"[\\[\]]")
# What a URI may hold as it is (RFC 3986 reserved and unreserved characters, and ``%`` so an
# existing escape is kept); anything else, a space or a non-ASCII character, is percent-encoded.
_URI_SAFE = ":/?#[]@!$&'()*+,;=%~"

_LEVEL_BY_SEVERITY = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


class SarifReporter:
    """Maps a scan result onto a single-run SARIF 2.1.0 document for CI code scanning."""

    fmt = "sarif"

    def render(self, result: ScanResult) -> str:
        """
        Args:
            result (ScanResult): The scan result.

        Returns:
            str: The SARIF document as indented JSON.
        """
        return json.dumps(self.to_dict(result), indent=2)

    def to_dict(self, result: ScanResult) -> dict[str, Any]:
        """
        Build the SARIF document as a plain dict.

        Args:
            result (ScanResult): The scan result.

        Returns:
            dict[str, Any]: One ``run`` with a ``rules`` entry per distinct
                check id and a ``results`` entry per finding.
        """
        rules = [_rule(finding) for finding in _unique_rules(result.findings)]
        return {
            "$schema": _SCHEMA_URI,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "WebVigil",
                            "informationUri": _INFORMATION_URI,
                            "version": result.metadata.tool_version,
                            "rules": rules,
                        }
                    },
                    "results": [_result(finding) for finding in result.findings],
                }
            ],
        }


def _unique_rules(findings: tuple[Finding, ...]) -> list[Finding]:
    """
    Args:
        findings (tuple[Finding, ...]): All findings.

    Returns:
        list[Finding]: One representative finding per distinct ``check_id``,
            first occurrence kept.
    """
    seen: dict[str, Finding] = {}
    for finding in findings:
        seen.setdefault(finding.check_id, finding)
    return list(seen.values())


def _rule(finding: Finding) -> dict[str, Any]:
    """
    Args:
        finding (Finding): A representative finding for one check.

    Returns:
        dict[str, Any]: The SARIF ``rules`` entry — id, PascalCase name, a short
            description built from the id, ``security-severity``, and a ``helpUri``
            when one of the references is an ``http(s)`` URL.
    """
    rule: dict[str, Any] = {
        "id": finding.check_id,
        "name": _pascal_case(finding.check_id),
        "shortDescription": {"text": f"WebVigil check {finding.check_id}"},
        "properties": {
            "tags": ["security"],
            "security-severity": _SECURITY_SEVERITY[finding.severity],
        },
    }
    help_uri = next((ref for ref in finding.references if is_http_url(ref)), None)
    if help_uri is not None:
        rule["helpUri"] = help_uri
    return rule


def _result(finding: Finding) -> dict[str, Any]:
    """
    Args:
        finding (Finding): A finding.

    Returns:
        dict[str, Any]: The SARIF ``results`` entry — rule id, level, message,
            a physical location (and a logical location for the parameter /
            header / cookie), and the stable fingerprint.
    """
    uri = quote(finding.location.url, safe=_URI_SAFE)
    location: dict[str, Any] = {
        "physicalLocation": {"artifactLocation": {"uri": uri}},
    }
    if finding.location.key:
        # The parameter / header / cookie the finding is about (spec 006 ADR-8).
        location["logicalLocations"] = [
            {
                "name": finding.location.key,
                "kind": "parameter" if finding.location.param else "member",
                "fullyQualifiedName": f"{finding.location.method} {uri}#{finding.location.key}",
            }
        ]
    return {
        "ruleId": finding.check_id,
        "level": _LEVEL_BY_SEVERITY[finding.severity],
        "message": {"text": _message(f"{finding.title}. {finding.description}")},
        "locations": [location],
        "partialFingerprints": {"webvigil/v1": finding.fingerprint},
    }


def _message(text: str) -> str:
    """
    Args:
        text (str): Plain text for a SARIF ``message``.

    Returns:
        str: ``text`` with every backslash and square bracket escaped, so a viewer shows it as
            written instead of rendering an embedded link.
    """
    return _MESSAGE_ESCAPE_RE.sub(lambda m: "\\" + m.group(), text)


def _pascal_case(check_id: str) -> str:
    """
    Args:
        check_id (str): A dotted, hyphenated check id.

    Returns:
        str: The id as a single PascalCase token, for the SARIF rule ``name``.
    """
    return "".join(
        part.capitalize() for part in check_id.replace(".", " ").replace("-", " ").split()
    )
