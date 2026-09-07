"""The DEPS checks: turn fingerprint detections into findings (spec 004, RF-09, RF-10).

Neither check issues HTTP — the fingerprint pass (ADR-1) has already run and left its
``Detection`` list on ``ctx.observations``. Each check also records the libraries it saw on
the technology inventory (RF-12).
"""

from __future__ import annotations

from collections.abc import Iterable
from functools import lru_cache

from webvigil.checks.base import Check
from webvigil.checks.deps.advisories import (
    Advisory,
    RetireJsProvider,
    default_provider,
    merge_advisories,
    numeric_version_key,
)
from webvigil.checks.registry import register
from webvigil.core.context import Detection, ScanContext
from webvigil.core.findings import (
    Category,
    Confidence,
    EvidenceItem,
    Finding,
    Location,
    ScanMode,
    Severity,
)
from webvigil.core.technology import DetectionMethod, Technology

_CONFIDENCE = {
    DetectionMethod.HASH: Confidence.HIGH,
    DetectionMethod.SRI: Confidence.HIGH,
    DetectionMethod.FILENAME: Confidence.MEDIUM,
    DetectionMethod.FILECONTENT: Confidence.MEDIUM,
    DetectionMethod.URI: Confidence.LOW,
}


@lru_cache(maxsize=1)
def _provider() -> RetireJsProvider:
    return default_provider()


def _technology(
    detection: Detection, *, vulnerable: bool, advisories: tuple[str, ...] = ()
) -> Technology:
    return Technology(
        name=detection.name,
        version=detection.version,
        detection=detection.method,
        source_url=detection.source_url,
        vulnerable=vulnerable,
        advisories=advisories,
    )


@register
class VulnerableLibraryCheck(Check):
    """A finding per detected library version with a known advisory."""

    id = "deps.js.vulnerable-library"
    name = "Vulnerable JavaScript library"
    category = Category.DEPS
    mode = ScanMode.PASSIVE
    default_severity = Severity.MEDIUM

    async def run(self, ctx: ScanContext) -> list[Finding]:
        provider = _provider()
        findings: list[Finding] = []
        for detection in ctx.observations.detections:
            if detection.version is None:
                continue
            # Merge the offline Retire.js match with any OSV.dev advisories the orchestrator's
            # opt-in lookup pass left on the context (spec 010, RF-08). Off by default: the
            # map is empty unless ``[deps] osv_online`` was set.
            advisories = merge_advisories(
                provider.match(detection.name, detection.version),
                ctx.observations.osv_advisories.get((detection.name, detection.version), ()),
            )
            if not advisories:
                ctx.observations.add_technology(_technology(detection, vulnerable=False))
                continue
            identifiers = _unique(i for advisory in advisories for i in advisory.identifiers)
            ctx.observations.add_technology(
                _technology(detection, vulnerable=True, advisories=identifiers)
            )
            findings.append(self._finding(ctx, detection, advisories, identifiers))
        return findings

    def _finding(
        self,
        ctx: ScanContext,
        detection: Detection,
        advisories: list[Advisory],
        identifiers: tuple[str, ...],
    ) -> Finding:
        top = max(advisories, key=lambda a: a.severity)
        cwe = _unique(c for advisory in advisories for c in advisory.cwe)
        references = _unique(url for advisory in advisories for url in advisory.info_urls) + tuple(
            f"https://cwe.mitre.org/data/definitions/{c}.html" for c in cwe
        )
        version = detection.version
        base = self.finding(
            title=f"{detection.name} {version} has known vulnerabilities",
            description=_describe(detection, advisories),
            remediation=_remediation(detection, advisories),
            severity=top.severity,
            confidence=_CONFIDENCE[detection.method],
            location=Location(url=detection.source_url or ctx.target.entry_url),
            dedup_key=f"{detection.name}@{version}",
            evidence=[
                EvidenceItem.of("Detection", f"{detection.method.value}: {detection.marker}"),
                EvidenceItem.of("Advisories", "\n".join(_advisory_lines(advisories))),
            ],
        )
        return base.model_copy(update={"cwe": cwe, "references": references})


@register
class LibraryDetectedCheck(Check):
    """An INFO finding per recognised library whose version could not be determined."""

    id = "deps.js.library-detected"
    name = "JavaScript library detected (version undetermined)"
    category = Category.DEPS
    mode = ScanMode.PASSIVE
    default_severity = Severity.INFO

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for detection in ctx.observations.detections:
            if detection.version is not None:
                continue
            ctx.observations.add_technology(_technology(detection, vulnerable=False))
            findings.append(
                self.finding(
                    title=f"{detection.name} detected, version undetermined",
                    description=(
                        f"WebVigil recognised {detection.name} on this target but could not "
                        "read its version, so it could not be checked against known "
                        "vulnerabilities."
                    ),
                    remediation="Confirm the library version and keep it up to date.",
                    confidence=Confidence.LOW,
                    location=Location(url=detection.source_url or ctx.target.entry_url),
                    dedup_key=f"{detection.name}@?",
                    evidence=[
                        EvidenceItem.of(
                            "Detection", f"{detection.method.value}: {detection.marker}"
                        )
                    ],
                )
            )
        return findings


def _describe(detection: Detection, advisories: list[Advisory]) -> str:
    lead = f"{detection.name} {detection.version} is affected by {len(advisories)} known "
    lead += "vulnerability:" if len(advisories) == 1 else "vulnerabilities:"
    return lead + "\n" + "\n".join(f"- {line}" for line in _advisory_lines(advisories))


def _advisory_lines(advisories: list[Advisory]) -> list[str]:
    lines: list[str] = []
    for advisory in advisories:
        ids = ", ".join(advisory.identifiers) if advisory.identifiers else "(no identifier)"
        summary = advisory.summary or "no summary provided"
        note = "" if advisory.severity_from_upstream else " [severity not supplied upstream]"
        lines.append(f"{ids}: {summary}{note}")
    return lines


def _remediation(detection: Detection, advisories: list[Advisory]) -> str:
    safe = [a.first_safe_version for a in advisories if a.first_safe_version]
    if safe:
        target = max(safe, key=numeric_version_key)
        return f"Upgrade {detection.name} to {target} or later."
    return f"Upgrade {detection.name} to the latest release."


def _unique[T](items: Iterable[T]) -> tuple[T, ...]:
    return tuple(dict.fromkeys(items))
