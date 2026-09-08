"""
The orchestrator: the one entry point that runs a whole scan (RF-11, RF-15).

Parse target → enforce the Active-Mode gate → crawl in scope → run the selected
checks concurrently against a shared context → dedupe findings → assemble a
:class:`~webvigil.core.result.ScanResult`.
"""

from __future__ import annotations

import asyncio
import traceback
from collections.abc import Sequence
from datetime import UTC, datetime

from webvigil import __version__
from webvigil.checks.base import Check
from webvigil.checks.deps.advisories import Advisory
from webvigil.checks.deps.fingerprint import Fingerprinter
from webvigil.checks.deps.osv import OsvLookupError, OsvProvider
from webvigil.checks.deps.rules import RetireJsRules
from webvigil.checks.deps.staleness import staleness_warning
from webvigil.checks.disclosure.catalogue import load_catalogue
from webvigil.checks.disclosure.probe import DisclosureProbe, ProbeHit
from webvigil.checks.envelope.scanner import EnvelopeHit, EnvelopeScanner
from webvigil.checks.injection.engine import KIND_BY_CHECK_ID, InjectionScanner
from webvigil.checks.injection.models import InjectionHit
from webvigil.checks.injection.stored import StoredXssScanner
from webvigil.checks.registry import iter_checks, load_plugins, unknown_check_ids
from webvigil.core.config import ScanConfig
from webvigil.core.context import Detection, Observations, Page, ScanContext
from webvigil.core.errors import ActiveModeNotAuthorized
from webvigil.core.findings import Category, Finding, ScanMode
from webvigil.core.result import CheckError, ScanMetadata, ScanResult
from webvigil.core.target import Target
from webvigil.core.technology import Technology
from webvigil.crawler.crawler import Crawler
from webvigil.crawler.forms import Form
from webvigil.crawler.openapi import ApiOperation, load_openapi
from webvigil.http.client import HttpClient

_PROBE_FAMILIES = frozenset({"vcs", "config", "manifest", "backup", "debug", "sourcemap"})
_STORED_CHECK_ID = "injection.xss.stored"
_ENVELOPE_CHECK_IDS = frozenset({"injection.host-header", "http.methods.unsafe"})


class Orchestrator:
    """
    Runs one scan from a raw target string to a :class:`~webvigil.core.result.ScanResult`.

    Attributes are private; construct one with a resolved config and call
    :meth:`run`.
    """

    def __init__(
        self,
        config: ScanConfig,
        *,
        check_types: Sequence[type[Check]] | None = None,
    ) -> None:
        """
        Args:
            config (ScanConfig): The fully resolved configuration for the scan.
            check_types (Sequence[type[Check]] | None): An explicit check set,
                bypassing registry discovery. Used by tests; ``None`` in normal
                operation.
        """
        self._config = config
        self._check_types = check_types

    async def run(self, raw_target: str) -> ScanResult:
        """
        Run a full scan and return its result.

        Parses ``raw_target``, enforces the Active-Mode gate, loads any
        ``--openapi`` document, crawls in scope, runs the fingerprint / OSV /
        disclosure-probe / injection passes, fans the selected checks over a
        shared context, dedupes, and assembles the result.

        Args:
            raw_target (str): The target as typed by the user; ``https://`` is
                assumed when no scheme is given.

        Returns:
            ScanResult: Metadata, deduplicated findings, detected technologies,
                per-check errors, and warnings.

        Raises:
            InvalidTargetError: If ``raw_target`` cannot be parsed.
            ActiveModeNotAuthorized: If Active Mode is requested without an
                ``authorized_by`` attestation.
            OpenApiError: If ``[scan] openapi`` is set but cannot be loaded
                (spec 013).
        """
        started_at = datetime.now(UTC)
        target = Target.parse(raw_target, scope=self._config.scan.scope)
        self._enforce_active_gate()

        warnings: list[str] = []
        if self._config.injection.stored_xss and self._config.scan.mode is not ScanMode.ACTIVE:
            warnings.append(
                "stored-XSS testing requires --mode active — the stored pass did not run"
            )
        technologies: tuple[Technology, ...] = ()
        async with HttpClient(target, self._config) as http:
            operations = await self._load_openapi(http, target, warnings)
            crawler = Crawler(
                http,
                target,
                self._config,
                extra_seeds=[op.url for op in operations if op.method == "GET"],
            )
            pages = tuple(await crawler.discover())
            forms = crawler.forms
            if crawler.skipped_destructive:
                warnings.append(
                    f"declined to follow {crawler.skipped_destructive} link(s) that look "
                    "state-changing (authenticated crawl)"
                )
            check_types = self._select_checks(warnings)
            detections = await self._fingerprint(check_types, http, target, pages, warnings)
            osv_advisories = await self._osv_lookup(check_types, detections, warnings)
            probe_hits = await self._probe_disclosure(check_types, http, target, pages, warnings)
            injection_hits = await self._inject(
                check_types, http, target, pages, forms, warnings, operations
            )
            stored_hits = await self._inject_stored(
                check_types, http, target, pages, forms, warnings
            )
            envelope_hits = await self._scan_envelope(
                check_types, http, target, pages, forms, warnings
            )
            context = ScanContext(
                config=self._config,
                target=target,
                http=http,
                pages=pages,
                entry=pages[0],
                forms=forms,
                observations=Observations(
                    detections=detections,
                    osv_advisories=osv_advisories,
                    probe_hits=probe_hits,
                    injection_hits=injection_hits + stored_hits,
                    envelope_hits=envelope_hits,
                ),
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
            authenticated=bool(self._config.auth.cookies or self._config.auth.headers),
        )
        return ScanResult(
            metadata=metadata,
            findings=deduped,
            technologies=technologies,
            errors=tuple(errors),
            warnings=tuple(warnings),
        )

    async def _load_openapi(
        self, http: HttpClient, target: Target, warnings: list[str]
    ) -> tuple[ApiOperation, ...]:
        """
        Load the ``[scan] openapi`` document into seed operations, before the crawl (spec 013).

        A no-op returning ``()`` when ``[scan] openapi`` is unset. A document
        that will not load is fatal (the user asked for it explicitly); a
        document that yields no operations is a warning and the scan continues.

        Args:
            http (HttpClient): The shared, scope-guarded HTTP client (used only
                for a URL source).
            target (Target): The normalized target.
            warnings (list[str]): Scan-level warning list, appended to in place.

        Returns:
            tuple[ApiOperation, ...]: The imported operations, or ``()``.

        Raises:
            OpenApiError: If the document cannot be read or is not a
                recognizable OpenAPI / Swagger document.
        """
        source = self._config.scan.openapi
        if not source:
            return ()
        operations, notes = await load_openapi(
            source,
            http=http,
            target=target,
            max_operations=self._config.scan.openapi_max_operations,
        )
        warnings.extend(notes)
        return tuple(operations)

    async def _fingerprint(
        self,
        check_types: Sequence[type[Check]],
        http: HttpClient,
        target: Target,
        pages: tuple[Page, ...],
        warnings: list[str],
    ) -> tuple[Detection, ...]:
        """
        Run the dependency fingerprint pass when a DEPS check is selected (ADR-1, ADR-3).

        A no-op returning ``()`` when no DEPS check is in ``check_types``.
        Appends any staleness or fingerprint notice to ``warnings`` in place.

        Args:
            check_types (Sequence[type[Check]]): The checks selected for the run.
            http (HttpClient): The shared, scope-guarded HTTP client.
            target (Target): The normalized target.
            pages (tuple[Page, ...]): The pages the crawler discovered.
            warnings (list[str]): Scan-level warning list, appended to in place.

        Returns:
            tuple[Detection, ...]: The libraries the pass identified.
        """
        if not any(check.category is Category.DEPS for check in check_types):
            return ()
        rules = RetireJsRules.load()
        warnings.extend(staleness_warning(rules))
        result = await Fingerprinter(http, target, rules).scan(pages)
        warnings.extend(result.warnings)
        return tuple(result.detections)

    async def _osv_lookup(
        self,
        check_types: Sequence[type[Check]],
        detections: tuple[Detection, ...],
        warnings: list[str],
    ) -> dict[tuple[str, str], tuple[Advisory, ...]]:
        """
        Query OSV.dev for the detected libraries when ``[deps] osv_online`` is on (spec 010).

        Opt-in and additive: a no-op returning ``{}`` when the flag is off, no
        DEPS check is selected, or nothing was detected with a version. On any
        lookup failure the scan keeps the offline Retire.js results and records
        a warning (RF-01, RF-03, RF-09, ADR-2).

        Args:
            check_types (Sequence[type[Check]]): The checks selected for the run.
            detections (tuple[Detection, ...]): Libraries from :meth:`_fingerprint`.
            warnings (list[str]): Scan-level warning list, appended to in place.

        Returns:
            dict[tuple[str, str], tuple[Advisory, ...]]: ``(name, version)`` ->
                OSV advisories, for the check to merge with the offline match.
        """
        if not self._config.deps.osv_online:
            return {}
        if not any(check.category is Category.DEPS for check in check_types):
            return {}
        versioned = tuple(d for d in detections if d.version is not None)
        if not versioned:
            return {}
        try:
            report = await OsvProvider(
                self._config.deps.osv_base_url,
                self._config.deps.osv_timeout_s,
                user_agent=self._config.http.user_agent,
            ).lookup(versioned)
        except OsvLookupError as exc:
            warnings.append(
                f"OSV.dev lookup failed: {exc}; reported advisories are from the offline "
                "database only"
            )
            return {}
        warnings.extend(report.warnings)
        return report.advisories

    async def _probe_disclosure(
        self,
        check_types: Sequence[type[Check]],
        http: HttpClient,
        target: Target,
        pages: tuple[Page, ...],
        warnings: list[str],
    ) -> tuple[ProbeHit, ...]:
        """
        Run the disclosure probe pass when ``probe`` is on and a probe-fed check is selected.

        A no-op returning ``()`` when ``[disclosure] probe`` is off or no
        probe-fed check is selected. Appends probe notices to ``warnings`` in
        place.

        Args:
            check_types (Sequence[type[Check]]): The checks selected for the run.
            http (HttpClient): The shared, scope-guarded HTTP client.
            target (Target): The normalized target.
            pages (tuple[Page, ...]): The pages the crawler discovered.
            warnings (list[str]): Scan-level warning list, appended to in place.

        Returns:
            tuple[ProbeHit, ...]: The sensitive paths the probe reached.
        """
        if not self._config.disclosure.probe:
            return ()
        if not any(getattr(check, "family", None) in _PROBE_FAMILIES for check in check_types):
            return ()
        report = await DisclosureProbe(http, target, load_catalogue(), pages).run()
        warnings.extend(report.warnings)
        return tuple(report.hits)

    async def _scan_envelope(
        self,
        check_types: Sequence[type[Check]],
        http: HttpClient,
        target: Target,
        pages: tuple[Page, ...],
        forms: tuple[Form, ...],
        warnings: list[str],
    ) -> tuple[EnvelopeHit, ...]:
        """
        Run the request-envelope pass when the scan is Active and a check it feeds is selected.

        A no-op returning ``()`` in Passive Mode or when neither
        ``injection.host-header`` nor ``http.methods.unsafe`` is selected. A pass
        bug is caught here and downgraded to a warning.

        Args:
            check_types (Sequence[type[Check]]): The checks selected for the run.
            http (HttpClient): The shared, scope-guarded HTTP client.
            target (Target): The normalized target.
            pages (tuple[Page, ...]): The pages the crawler discovered.
            forms (tuple[Form, ...]): The parsed ``<form>`` inventory.
            warnings (list[str]): Scan-level warning list, appended to in place.

        Returns:
            tuple[EnvelopeHit, ...]: The confirmed host-header / HTTP-methods hits.
        """
        if self._config.scan.mode is not ScanMode.ACTIVE:
            return ()
        if not any(check.id in _ENVELOPE_CHECK_IDS for check in check_types):
            return ()
        try:
            scanner = EnvelopeScanner(http, target, self._config, pages, forms)
            hits = await scanner.run()
        except Exception as exc:  # a pass bug must not abort the whole scan
            warnings.append(f"request-envelope pass failed: {exc or type(exc).__name__}")
            return ()
        warnings.extend(scanner.warnings)
        return tuple(hits)

    async def _inject(
        self,
        check_types: Sequence[type[Check]],
        http: HttpClient,
        target: Target,
        pages: tuple[Page, ...],
        forms: tuple[Form, ...],
        warnings: list[str],
        operations: tuple[ApiOperation, ...] = (),
    ) -> tuple[InjectionHit, ...]:
        """
        Run the active-injection pass when the scan is Active and a check is selected.

        A no-op returning ``()`` in Passive Mode or when no injection check is
        selected. A detector bug is caught here and downgraded to a warning so
        it cannot abort the whole scan.

        Args:
            check_types (Sequence[type[Check]]): The checks selected for the run.
            http (HttpClient): The shared, scope-guarded HTTP client.
            target (Target): The normalized target.
            pages (tuple[Page, ...]): The pages the crawler discovered.
            forms (tuple[Form, ...]): The parsed ``<form>`` inventory.
            warnings (list[str]): Scan-level warning list, appended to in place.
            operations (tuple[ApiOperation, ...]): Operations from an
                ``--openapi`` import, expanded into extra injection points
                (spec 013). Defaults to empty.

        Returns:
            tuple[InjectionHit, ...]: The confirmed reflected-injection hits.
        """
        if self._config.scan.mode is not ScanMode.ACTIVE:
            return ()
        selected = {
            KIND_BY_CHECK_ID[check.id] for check in check_types if check.id in KIND_BY_CHECK_ID
        }
        if not selected:
            return ()
        try:
            report = await InjectionScanner(
                http,
                target,
                self._config.injection,
                pages,
                forms,
                selected,
                operations=operations,
            ).run()
        except Exception as exc:  # a detector bug must not abort the whole scan
            warnings.append(f"active injection pass failed: {exc or type(exc).__name__}")
            return ()
        warnings.extend(report.warnings)
        return tuple(report.hits)

    async def _inject_stored(
        self,
        check_types: Sequence[type[Check]],
        http: HttpClient,
        target: Target,
        pages: tuple[Page, ...],
        forms: tuple[Form, ...],
        warnings: list[str],
    ) -> tuple[InjectionHit, ...]:
        """
        Run the two-phase stored-XSS pass (spec 008) when it is Active, selected, opted in.

        A no-op returning ``()`` in Passive Mode, when ``[injection] stored_xss``
        is off, or when the stored-XSS check is not selected. A detector bug is
        caught here and downgraded to a warning.

        Args:
            check_types (Sequence[type[Check]]): The checks selected for the run.
            http (HttpClient): The shared, scope-guarded HTTP client.
            target (Target): The normalized target.
            pages (tuple[Page, ...]): The pages the crawler discovered.
            forms (tuple[Form, ...]): The parsed ``<form>`` inventory.
            warnings (list[str]): Scan-level warning list, appended to in place.

        Returns:
            tuple[InjectionHit, ...]: The confirmed stored-XSS hits.
        """
        if self._config.scan.mode is not ScanMode.ACTIVE:
            return ()
        if not self._config.injection.stored_xss:
            return ()
        if not any(check.id == _STORED_CHECK_ID for check in check_types):
            return ()
        try:
            report = await StoredXssScanner(http, target, self._config, pages, forms).run()
        except Exception as exc:  # a detector bug must not abort the whole scan
            warnings.append(f"stored-XSS pass failed: {exc or type(exc).__name__}")
            return ()
        warnings.extend(report.warnings)
        return tuple(report.hits)

    def _enforce_active_gate(self) -> None:
        """
        Refuse to proceed in Active Mode without an authorization attestation.

        Raises:
            ActiveModeNotAuthorized: In Active Mode when ``[active].authorized_by``
                is absent or blank.
        """
        if self._config.scan.mode is not ScanMode.ACTIVE:
            return
        if self._config.active is None or not self._config.active.authorized_by.strip():
            raise ActiveModeNotAuthorized(
                "Active Mode requires an authorization: pass --authorized-by "
                '"<name / engagement>" (or set [active].authorized_by in the config).'
            )

    def _select_checks(self, warnings: list[str]) -> list[type[Check]]:
        """
        Resolve the checks to run: the explicit set if given, else registry discovery.

        Loads plugins, then filters the registry by scan mode and the
        configured disabled list. An unknown id in that list becomes a warning,
        not an error.

        Args:
            warnings (list[str]): Scan-level warning list, appended to in place.

        Returns:
            list[type[Check]]: The check classes to instantiate and run.
        """
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
        """
        Instantiate and run every selected check concurrently over one shared context.

        Each check runs in its own task; one that raises is recorded as a
        :class:`~webvigil.core.result.CheckError` instead of failing the group.

        Args:
            check_types (Sequence[type[Check]]): The check classes to run.
            context (ScanContext): The shared, read-only scan context.

        Returns:
            tuple[list[Finding], list[CheckError]]: The findings every check
                produced, and one entry per check that raised.
        """
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
    """
    Drop findings whose fingerprint has already been seen, keeping the first.

    Args:
        findings (Sequence[Finding]): The findings from every check, in run
            order.

    Returns:
        tuple[Finding, ...]: The findings with duplicates removed, order
            preserved.
    """
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        unique.append(finding)
    return tuple(unique)
