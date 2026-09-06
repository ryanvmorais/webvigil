"""SARIF 2.1.0 reporter (RF-22, ADR-7).

The document is built by hand — a small, fixed slice of SARIF. A schema test guards the
mapping.
"""

from __future__ import annotations

import json
from typing import Any

from webvigil.core.findings import Finding, Severity
from webvigil.core.result import ScanResult

_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
_INFORMATION_URI = "https://github.com/ryanvmorais/webvigil"

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
    fmt = "sarif"

    def render(self, result: ScanResult) -> str:
        return json.dumps(self.to_dict(result), indent=2)

    def to_dict(self, result: ScanResult) -> dict[str, Any]:
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
    seen: dict[str, Finding] = {}
    for finding in findings:
        seen.setdefault(finding.check_id, finding)
    return list(seen.values())


def _rule(finding: Finding) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": finding.check_id,
        "name": _pascal_case(finding.check_id),
        "shortDescription": {"text": finding.title},
        "properties": {
            "tags": ["security"],
            "security-severity": _SECURITY_SEVERITY[finding.severity],
        },
    }
    if finding.references:
        rule["helpUri"] = finding.references[0]
    return rule


def _result(finding: Finding) -> dict[str, Any]:
    location: dict[str, Any] = {
        "physicalLocation": {"artifactLocation": {"uri": finding.location.url}},
    }
    if finding.location.key:
        # The parameter / header / cookie the finding is about (spec 006 ADR-8).
        location["logicalLocations"] = [
            {
                "name": finding.location.key,
                "kind": "parameter" if finding.location.param else "member",
                "fullyQualifiedName": (
                    f"{finding.location.method} {finding.location.url}#{finding.location.key}"
                ),
            }
        ]
    return {
        "ruleId": finding.check_id,
        "level": _LEVEL_BY_SEVERITY[finding.severity],
        "message": {"text": f"{finding.title}. {finding.description}"},
        "locations": [location],
        "partialFingerprints": {"webvigil/v1": finding.fingerprint},
    }


def _pascal_case(check_id: str) -> str:
    return "".join(
        part.capitalize() for part in check_id.replace(".", " ").replace("-", " ").split()
    )
