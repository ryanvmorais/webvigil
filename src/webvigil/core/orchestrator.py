"""The orchestrator: the one entry point that runs a whole scan (RF-11, RF-15).

Parse target → enforce the Active-Mode gate → crawl in scope → run the selected checks
concurrently against a shared context → dedupe findings → assemble a ``ScanResult``.
"""

from __future__ import annotations

import asyncio
import traceback
from collections.abc import Sequence
from datetime import UTC, datetime

from webvigil import __version__
from webvigil.checks.base import Check
from webvigil.checks.deps.fingerprint import Fingerprinter
from webvigil.checks.deps.rules import RetireJsRules
from webvigil.checks.deps.staleness import staleness_warning
from webvigil.checks.disclosure.catalogue import load_catalogue
from webvigil.checks.disclosure.probe import DisclosureProbe, ProbeHit
from webvigil.checks.registry import iter_checks, load_plugins, unknown_check_ids
from webvigil.core.config import ScanConfig
from webvigil.core.context import Detection, Observations, Page, ScanContext
from webvigil.core.errors import ActiveModeNotAuthorized
from webvigil.core.findings import Category, Finding, ScanMode
from webvigil.core.result import CheckError, ScanMetadata, ScanResult
from webvigil.core.target import Target
from webvigil.core.technology import Technology
from webvigil.crawler.crawler import Crawler
from webvigil.http.client import HttpClient

_PROBE_FAMILIES = frozenset({"vcs", "config", "manifest", "backup", "debug", "sourcemap"})


class Orchestrator:
    """Runs one scan from a raw target string to a :class:`ScanResult`."""

    def __init__(
        self,
        config: ScanConfig,
        *,
        check_types: Sequence[type[Check]] | None = None,
    ) -> None:
        self._config = config
        self._check_types = check_types

    async def run(self, raw_target: str) -> ScanResult:
        started_at = datetime.now(UTC)
        target = Target.parse(raw_target, scope=self._config.scan.scope)
        self._enforce_active_gate()

        warnings: list[str] = []
        technologies: tuple[Technology, ...] = ()
        async with HttpClient(target, self._config) as http:
            pages = tuple(await Crawler(http, target, self._config).discover())
            check_types = self._select_checks(warnings)
            detections = await self._fingerprint(check_types, http, target, pages, warnings)
            probe_hits = await self._probe_disclosure(check_types, http, target, pages, warnings)
            context = ScanContext(
                config=self._config,
                target=target,
                http=http,
                pages=pages,
                entry=pages[0],
                observations=Observations(detections=detections, probe_hits=probe_hits),
            )
            findings, errors = await self._run_checks(check_types, context)
            warnings.extend(context.observations.warnings)
            technologies = context.observations.technologies

        deduped = _dedupe(findings)
        metadata = ScanMetadata(
            target=target.entry_url,
            mode=self._config.scan.mode,
            scope=self._config.scan.scope,
            authorized_by=self._config.active.authorized_by if self._config.active else None,
            tool_version=__version__,
            started_at=started_at,
            finished_at=datetime.now(UTC),
            pages_scanned=len(pages),
            counts=ScanResult.severity_counts(deduped),
        )
        return ScanResult(
            metadata=metadata,
            findings=deduped,
            technologies=technologies,
            errors=tuple(errors),
            warnings=tuple(warnings),
        )

    async def _fingerprint(
        self,
        check_types: Sequence[type[Check]],
        http: HttpClient,
        target: Target,
        pages: tuple[Page, ...],
        warnings: list[str],
    ) -> tuple[Detection, ...]:
        """Run the dependency fingerprint pass when a DEPS check is selected (ADR-1, ADR-3)."""
        if not any(check.category is Category.DEPS for check in check_types):
            return ()
        rules = RetireJsRules.load()
        warnings.extend(staleness_warning(rules))
        result = await Fingerprinter(http, target, rules).scan(pages)
        warnings.extend(result.warnings)
        return tuple(result.detections)

    async def _probe_disclosure(
        self,
        check_types: Sequence[type[Check]],
        http: HttpClient,
        target: Target,
        pages: tuple[Page, ...],
        warnings: list[str],
    ) -> tuple[ProbeHit, ...]:
        """Run the disclosure probe pass when ``probe`` is on and a probe-fed check is selected."""
        if not self._config.disclosure.probe:
            return ()
        if not any(getattr(check, "family", None) in _PROBE_FAMILIES for check in check_types):
            return ()
        report = await DisclosureProbe(http, target, load_catalogue(), pages).run()
        warnings.extend(report.warnings)
        return tuple(report.hits)

    def _enforce_active_gate(self) -> None:
        if self._config.scan.mode is not ScanMode.ACTIVE:
            return
        if self._config.active is None or not self._config.active.authorized_by.strip():
            raise ActiveModeNotAuthorized(
                "Active Mode requires an authorization: pass --authorized-by "
                '"<name / engagement>" (or set [active].authorized_by in the config).'
            )

    def _select_checks(self, warnings: list[str]) -> list[type[Check]]:
        if self._check_types is not None:
            return list(self._check_types)
        load_plugins()
        warnings.extend(
            f"unknown disabled check id: {check_id}"
            for check_id in unknown_check_ids(self._config.checks.disabled)
        )
        return iter_checks(
            mode=self._config.scan.mode,
            disabled=self._config.checks.disabled,
        )

    async def _run_checks(
        self, check_types: Sequence[type[Check]], context: ScanContext
    ) -> tuple[list[Finding], list[CheckError]]:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        async def _run_one(check_cls: type[Check]) -> None:
            try:
                produced = await check_cls().run(context)
            except Exception as exc:
                errors.append(
                    CheckError(
                        check_id=check_cls.id,
                        message=str(exc) or type(exc).__name__,
                        traceback="".join(traceback.format_exception(exc)),
                    )
                )
                return
            findings.extend(produced)

        async with asyncio.TaskGroup() as group:
            for check_cls in check_types:
                group.create_task(_run_one(check_cls))
        return findings, errors


def _dedupe(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        unique.append(finding)
    return tuple(unique)
