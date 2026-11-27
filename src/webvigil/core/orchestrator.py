"""
The orchestrator: the one entry point that runs a whole scan (RF-11, RF-15).

Parse target → enforce the Active-Mode gate → crawl in scope → run the selected
checks concurrently against a shared context → dedupe findings → assemble a
:class:`~webvigil.core.result.ScanResult`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime

from webvigil import __version__
from webvigil.auth.login import Authenticator, Credentials
from webvigil.auth.scrub import scrub_result
from webvigil.checks.base import Check
from webvigil.checks.csrf.scanner import CsrfHit, CsrfScanner
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
from webvigil.checks.session.scanner import SessionHit, SessionScanner, kinds_for
from webvigil.checks.upload.scanner import UploadHit, UploadScanner
from webvigil.core.config import LoginSection, ScanConfig
from webvigil.core.context import Detection, Observations, Page, ScanContext
from webvigil.core.errors import (
    ActiveModeNotAuthorized,
    TargetUnreachableError,
    WebVigilError,
)
from webvigil.core.findings import Category, Finding, ScanMode
from webvigil.core.html import track_partial_parses
from webvigil.core.output import portable_traceback
from webvigil.core.result import CheckError, ScanMetadata, ScanResult
from webvigil.core.secrets import collect_secrets
from webvigil.core.target import Target
from webvigil.core.technology import Technology
from webvigil.crawler.crawler import Crawler
from webvigil.crawler.forms import Form
from webvigil.crawler.har import load_har, merge_operations
from webvigil.crawler.jsapp import script_app_warning
from webvigil.crawler.openapi import ApiOperation, load_openapi
from webvigil.http.addresses import address_warnings
from webvigil.http.client import (
    HttpClient,
    blocked_address_warning,
    truncated_warning,
    unreachable_warning,
)
from webvigil.http.session import Session

_PROBE_FAMILIES = frozenset({"vcs", "config", "manifest", "backup", "debug", "sourcemap"})
_STORED_CHECK_ID = "injection.xss.stored"
_ENVELOPE_CHECK_IDS = frozenset({"injection.host-header", "http.methods.unsafe"})
_UPLOAD_CHECK_ID = "upload.unrestricted"
_CSRF_CHECK_ID = "csrf.form.token-not-enforced"
# Distinct findings one check keeps in one scan. A check that reports one finding per item the
# scanned site lists limits itself per page; this bounds the report and the stored scan when a
# check does not, or when many pages each reach their own limit.
FINDINGS_PER_CHECK_CAP = 5_000
# Warnings one scan result keeps. Each pass warns once per limit it reaches, so a real scan has
# a few dozen; this bounds the report and the stored scan whatever the passes queued.
WARNINGS_CAP = 500


class _PassFailure(str):
    """A scan warning saying a pass raised, so what it would have found is missing."""

    __slots__ = ()


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
        credentials: Credentials | None = None,
    ) -> None:
        """
        Args:
            config (ScanConfig): The fully resolved configuration for the scan.
            check_types (Sequence[type[Check]] | None): An explicit check set,
                bypassing registry discovery. Used by tests; ``None`` in normal
                operation.
            credentials (Credentials | None): The account for ``[auth.login]``
                (spec 019). ``None`` reads the password from the environment variable
                the login names.
        """
        self._config = config
        self._check_types = check_types
        self._credentials = credentials

    async def run(self, raw_target: str) -> ScanResult:
        """
        Run a full scan and return its result.

        Parses ``raw_target``, enforces the Active-Mode gate, loads any
        ``--openapi`` document and ``--har`` recording, crawls in scope, runs the
        fingerprint / OSV / disclosure-probe / injection passes, fans the selected
        checks over a shared context, dedupes, and assembles the result.

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
            TargetUnreachableError: If no page of the target answered.
            OpenApiError: If ``[scan] openapi`` is set but cannot be loaded
                (spec 013).
            HarError: If ``[scan] har`` is set but cannot be loaded (spec 021).
        """
        started_at = datetime.now(UTC)
        target = Target.parse(raw_target, scope=self._config.scan.scope)
        self._enforce_active_gate()
        partial_parses = track_partial_parses()

        warnings: list[str] = []
        if self._config.injection.stored_xss and self._config.scan.mode is not ScanMode.ACTIVE:
            warnings.append(
                "stored-XSS testing requires --mode active — the stored pass did not run"
            )
        if self._config.injection.file_upload and self._config.scan.mode is not ScanMode.ACTIVE:
            warnings.append(
                "file-upload testing requires --mode active — the upload pass did not run"
            )
        if self._config.injection.csrf_confirm and self._config.scan.mode is not ScanMode.ACTIVE:
            warnings.append("CSRF confirmation requires --mode active — the CSRF pass did not run")
        if self._config.scan.submit_post_forms and self._config.scan.mode is not ScanMode.ACTIVE:
            warnings.append("POST crawling requires --mode active — the POST phase did not run")
        if self._config.session.test_logout and (
            self._config.scan.mode is not ScanMode.ACTIVE or self._config.auth.login is None
        ):
            warnings.append(
                "the logout test requires --mode active and a login - the logout test did not run"
            )
        technologies: tuple[Technology, ...] = ()
        session: Session | None = None
        async with HttpClient(target, self._config) as http:
            authenticator = await self._log_in(http, target, warnings)
            session = authenticator.session if authenticator is not None else None
            operations = tuple(
                merge_operations(
                    await self._load_openapi(http, target, warnings),
                    self._load_har(target, warnings),
                )
            )
            crawler = Crawler(
                http,
                target,
                self._config,
                extra_seeds=[op.seed_url for op in operations if op.method == "GET"],
                post_operations=[op for op in operations if op.method == "POST"],
            )
            pages = tuple(await crawler.discover())
            # A page that never answered has no headers: judging it would report them as missing.
            entry = next((page for page in pages if page.ok), None)
            if entry is None:
                raise TargetUnreachableError(f"the target did not answer: {pages[0].error}")
            if crawler.post_summary is not None and (line := crawler.post_summary.warning()):
                warnings.append(line)
            if line := script_app_warning(pages, har=bool(self._config.scan.har)):
                warnings.append(line)
            if line := crawler.limit_warning:
                warnings.append(line)
            forms = crawler.forms
            if crawler.skipped_destructive:
                warnings.append(
                    f"declined to follow {crawler.skipped_destructive} link(s) that look "
                    "state-changing"
                )
            if crawler.robots_unreadable is not None:
                warnings.append(
                    f"robots.txt could not be read ({crawler.robots_unreadable}): only the target "
                    "URL was crawled; set follow_robots = false under [scan] to crawl without it"
                )
            elif crawler.skipped_by_robots:
                warnings.append(
                    f"robots.txt kept the crawler from {crawler.skipped_by_robots} URL(s) "
                    f"({len(pages)} page(s) crawled): set follow_robots = false under [scan] "
                    "to crawl them on a site you are authorized to scan"
                )
            check_types = self._select_checks(warnings)
            detections = await self._fingerprint(check_types, http, target, pages, warnings)
            osv_advisories = await self._osv_lookup(check_types, http, detections, warnings)
            probe_hits = await self._probe_disclosure(check_types, http, target, pages, warnings)
            injection_hits = await self._inject(
                check_types, http, target, pages, forms, warnings, operations
            )
            stored_hits = await self._inject_stored(
                check_types, http, target, pages, forms, warnings, crawler
            )
            envelope_hits = await self._scan_envelope(
                check_types, http, target, pages, forms, warnings
            )
            upload_hits = await self._scan_upload(check_types, http, target, pages, forms, warnings)
            # Last: the one pass whose requests change server state (spec 017, ADR-6).
            csrf_hits = await self._scan_csrf(check_types, http, target, pages, forms, warnings)
            # Then the session checks (spec 020): their logout test ends the session, so it is last.
            session_hits = await self._scan_session(
                check_types, http, target, pages, forms, authenticator, warnings
            )
            context = ScanContext(
                config=self._config,
                target=target,
                http=http,
                pages=pages,
                entry=entry,
                forms=forms,
                observations=Observations(
                    detections=detections,
                    osv_advisories=osv_advisories,
                    probe_hits=probe_hits,
                    injection_hits=injection_hits + stored_hits,
                    envelope_hits=envelope_hits,
                    upload_hits=upload_hits,
                    csrf_hits=csrf_hits,
                    session_hits=session_hits,
                ),
            )
            findings, errors = await self._run_checks(check_types, context)
            warnings.extend(context.observations.warnings)
            if line := unreachable_warning(http.stats):
                warnings.append(line)
            if line := truncated_warning(http.stats, self._config.http.max_body_bytes):
                warnings.append(line)
            warnings.extend(partial_parses.warnings())
            if http.stats.deadline_reached:
                warnings.append(
                    f"the scan reached [scan] max_duration_s "
                    f"({self._config.scan.max_duration_s:g} s) and sent no request after it: "
                    "the report covers what was found until then"
                )
            if line := blocked_address_warning(http.stats):
                warnings.append(line)
            warnings.extend(address_warnings(http.addresses.notices()))
            technologies = context.observations.technologies
            if session is not None:
                warnings.extend(session.warnings())

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
            authenticated=bool(
                self._config.auth.cookies or self._config.auth.headers or session is not None
            ),
            login=session.summary() if session is not None else None,
        )
        result = ScanResult(
            metadata=metadata,
            findings=deduped,
            technologies=technologies,
            errors=tuple(errors),
            warnings=_cap_warnings(warnings),
            pass_failed=any(isinstance(warning, _PassFailure) for warning in warnings),
        )
        # spec 019, RF-11: a target may have reflected the password, a configured cookie or
        # header, or a session id into a page. Spec 024, RF-07: the list is every secret the
        # scan held, collected rather than assembled by hand; what the user gave is always
        # scrubbed, the jar's values only when they look like a session id. The password is the
        # one the login used, which may have come from the environment.
        credentials = authenticator.credentials if authenticator is not None else None
        secrets = collect_secrets(self._config, credentials)
        if session is not None:
            secrets |= session.secrets
        return scrub_result(result, secrets)

    async def _log_in(
        self, http: HttpClient, target: Target, warnings: list[str]
    ) -> Authenticator | None:
        """
        Run the automated login (spec 019) when one is configured and the scan is Active.

        Args:
            http (HttpClient): The open client; the session is attached to it.
            target (Target): The scan target.
            warnings (list[str]): The scan warnings; a Passive scan with a login configured
                says nothing was attempted, an unconfirmed login says so.

        Returns:
            Authenticator | None: The authenticator (its ``session`` is attached to ``http``),
                or ``None`` when no login ran.

        Raises:
            LoginFailedError: If the login fails — the scan stops before the crawl.
        """
        login: LoginSection | None = self._config.auth.login
        if login is None:
            return None
        if self._config.scan.mode is not ScanMode.ACTIVE:
            warnings.append("a login requires --mode active - no login was attempted")
            return None
        credentials = self._credentials or Credentials.from_environment(
            login.username, login.password_env
        )
        authenticator = Authenticator(http, target, login, credentials)
        http.use_session(authenticator.session)
        outcome = await authenticator.login()
        authenticator.session.confirmed = outcome.confirmed
        return authenticator

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

    def _load_har(self, target: Target, warnings: list[str]) -> tuple[ApiOperation, ...]:
        """
        Load the ``[scan] har`` recording into seed operations, before the crawl (spec 021).

        A no-op returning ``()`` when ``[scan] har`` is unset. The file is local, so nothing is
        sent. A file that will not load is fatal (the user asked for it explicitly); a file that
        yields no operations is a warning. One summary warning always says what was read,
        seeded and ignored, and one more says so when the recording looks authenticated and the
        scan carries no credentials of its own (the session in the file is never used).

        Args:
            target (Target): The normalized target.
            warnings (list[str]): Scan-level warning list, appended to in place.

        Returns:
            tuple[ApiOperation, ...]: The imported operations, or ``()``.

        Raises:
            HarError: If the file cannot be read or is not a HAR document.
        """
        source = self._config.scan.har
        if not source:
            return ()
        imported = load_har(
            source, target=target, max_operations=self._config.scan.har_max_operations
        )
        warnings.extend(imported.warnings)
        warnings.append(imported.summary())
        auth = self._config.auth
        if imported.authenticated and not (auth.cookies or auth.headers or auth.login):
            warnings.append(
                "the HAR recording looks authenticated, but this scan is not: give it --cookie, "
                "--header or --login-url to reach those routes with a session"
            )
        return tuple(imported.operations)

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
        Appends any staleness or fingerprint notice to ``warnings`` in place. A pass
        bug is caught here and downgraded to a warning.

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
        try:
            # the vendored rules load here, so a file that cannot be read fails this pass only
            rules = RetireJsRules.load()
            warnings.extend(staleness_warning(rules))
            result = await Fingerprinter(http, target, rules).scan(pages)
        except Exception as exc:  # a pass bug must not abort the whole scan
            warnings.append(
                _PassFailure(f"dependency fingerprint pass failed: {type(exc).__name__}")
            )
            return ()
        warnings.extend(result.warnings)
        return tuple(result.detections)

    async def _osv_lookup(
        self,
        check_types: Sequence[type[Check]],
        http: HttpClient,
        detections: tuple[Detection, ...],
        warnings: list[str],
    ) -> dict[tuple[str, str], tuple[Advisory, ...]]:
        """
        Query OSV.dev for the detected libraries when ``[deps] osv_online`` is on (spec 010).

        Opt-in and additive: a no-op returning ``{}`` when the flag is off, no
        DEPS check is selected, or nothing was detected with a version. On any
        lookup failure the scan keeps the offline Retire.js results and records
        a warning (RF-01, RF-03, RF-09, ADR-2). The lookup has its own client, so the
        scan's ``[scan] max_duration_s`` is applied to it here: past it, the lookup stops
        the same way.

        Args:
            check_types (Sequence[type[Check]]): The checks selected for the run.
            http (HttpClient): The scan's client, which holds the scan deadline.
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
            async with asyncio.timeout_at(http.deadline):
                report = await OsvProvider(
                    self._config.deps.osv_base_url,
                    self._config.deps.osv_timeout_s,
                    user_agent=self._config.http.user_agent,
                ).lookup(versioned)
        except TimeoutError:
            http.past_deadline()  # records that the scan reached its deadline
            warnings.append(
                "OSV.dev lookup stopped at [scan] max_duration_s; reported advisories are from "
                "the offline database only"
            )
            return {}
        except OsvLookupError as exc:
            warnings.append(
                f"OSV.dev lookup failed: {exc}; reported advisories are from the offline "
                "database only"
            )
            return {}
        except Exception as exc:  # a third party's answer must not abort the whole scan
            warnings.append(
                f"OSV.dev lookup failed ({type(exc).__name__}); reported advisories are from "
                "the offline database only"
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
        place. A pass bug is caught here and downgraded to a warning.

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
        try:
            # the vendored catalogue loads here, so a file that cannot be read fails this pass only
            report = await DisclosureProbe(http, target, load_catalogue(), pages).run()
        except Exception as exc:  # a pass bug must not abort the whole scan
            warnings.append(_PassFailure(f"disclosure probe pass failed: {type(exc).__name__}"))
            return ()
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
            warnings.append(_PassFailure(f"request-envelope pass failed: {type(exc).__name__}"))
            return ()
        warnings.extend(scanner.warnings)
        return tuple(hits)

    async def _scan_upload(
        self,
        check_types: Sequence[type[Check]],
        http: HttpClient,
        target: Target,
        pages: tuple[Page, ...],
        forms: tuple[Form, ...],
        warnings: list[str],
    ) -> tuple[UploadHit, ...]:
        """
        Run the file-upload pass when it is Active, selected, and opted in (spec 014).

        A no-op returning ``()`` in Passive Mode, when ``[injection] file_upload``
        is off, or when ``upload.unrestricted`` is not selected. A pass bug is
        caught here and downgraded to a warning.

        Args:
            check_types (Sequence[type[Check]]): The checks selected for the run.
            http (HttpClient): The shared, scope-guarded HTTP client.
            target (Target): The normalized target.
            pages (tuple[Page, ...]): The pages the crawler discovered.
            forms (tuple[Form, ...]): The parsed ``<form>`` inventory.
            warnings (list[str]): Scan-level warning list, appended to in place.

        Returns:
            tuple[UploadHit, ...]: The confirmed unrestricted-upload hits.
        """
        if self._config.scan.mode is not ScanMode.ACTIVE:
            return ()
        if not self._config.injection.file_upload:
            return ()
        if not any(check.id == _UPLOAD_CHECK_ID for check in check_types):
            return ()
        try:
            scanner = UploadScanner(http, target, self._config, pages, forms)
            hits = await scanner.run()
        except Exception as exc:  # a pass bug must not abort the whole scan
            warnings.append(_PassFailure(f"file-upload pass failed: {type(exc).__name__}"))
            return ()
        warnings.extend(scanner.warnings)
        return tuple(hits)

    async def _scan_session(
        self,
        check_types: Sequence[type[Check]],
        http: HttpClient,
        target: Target,
        pages: tuple[Page, ...],
        forms: tuple[Form, ...],
        authenticator: Authenticator | None,
        warnings: list[str],
    ) -> tuple[SessionHit, ...]:
        """
        Run the session-security pass when any ``session.*`` check is selected (spec 020).

        The pass judges the session ids the crawl saw, samples anonymous visits when
        ``[session] sample_ids`` is on, compares the cookies across the login, and, with
        ``[session] test_logout`` and a login, logs out and replays the old session last.
        A pass bug is caught here and downgraded to a warning.

        Args:
            check_types (Sequence[type[Check]]): The checks selected for the run.
            http (HttpClient): The shared, scope-guarded HTTP client.
            target (Target): The normalized target.
            pages (tuple[Page, ...]): The pages the crawler discovered.
            forms (tuple[Form, ...]): The parsed ``<form>`` inventory.
            authenticator (Authenticator | None): The login's authenticator, if one ran.
            warnings (list[str]): Scan-level warning list, appended to in place.

        Returns:
            tuple[SessionHit, ...]: What the pass observed; ``()`` when no ``session.*`` check is
                selected.
        """
        kinds = kinds_for([check.id for check in check_types])
        if not self._config.session.test_logout:
            kinds -= {"logout"}
        if not kinds:
            return ()
        try:
            scanner = SessionScanner(
                http,
                target,
                self._config,
                pages,
                forms,
                session=authenticator.session if authenticator is not None else None,
                authenticator=authenticator,
                kinds=kinds,
            )
            hits = await scanner.run()
        except Exception as exc:  # a pass bug must not abort the whole scan
            warnings.append(_PassFailure(f"session checks failed: {type(exc).__name__}"))
            return ()
        warnings.extend(scanner.warnings)
        return tuple(hits)

    async def _scan_csrf(
        self,
        check_types: Sequence[type[Check]],
        http: HttpClient,
        target: Target,
        pages: tuple[Page, ...],
        forms: tuple[Form, ...],
        warnings: list[str],
    ) -> tuple[CsrfHit, ...]:
        """
        Run the active CSRF confirmation pass when it is Active, selected, and opted in (spec 017).

        A no-op returning ``()`` in Passive Mode, when ``[injection] csrf_confirm``
        is off, or when ``csrf.form.token-not-enforced`` is not selected. A pass bug
        is caught here and downgraded to a warning.

        Args:
            check_types (Sequence[type[Check]]): The checks selected for the run.
            http (HttpClient): The shared, scope-guarded HTTP client.
            target (Target): The normalized target.
            pages (tuple[Page, ...]): The pages the crawler discovered.
            forms (tuple[Form, ...]): The parsed ``<form>`` inventory.
            warnings (list[str]): Scan-level warning list, appended to in place.

        Returns:
            tuple[CsrfHit, ...]: The forms the server accepted without a valid token.
        """
        if self._config.scan.mode is not ScanMode.ACTIVE:
            return ()
        if not self._config.injection.csrf_confirm:
            return ()
        if not any(check.id == _CSRF_CHECK_ID for check in check_types):
            return ()
        try:
            scanner = CsrfScanner(http, target, self._config, pages, forms)
            hits = await scanner.run()
        except Exception as exc:  # a pass bug must not abort the whole scan
            warnings.append(_PassFailure(f"CSRF confirmation pass failed: {type(exc).__name__}"))
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
            warnings.append(_PassFailure(f"active injection pass failed: {type(exc).__name__}"))
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
        crawler: Crawler | None = None,
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
            crawler (Crawler | None): The first crawl's crawler, whose page-text allowance
                the re-crawl shares.

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
            report = await StoredXssScanner(
                http, target, self._config, pages, forms, crawler=crawler
            ).run()
        except Exception as exc:  # a detector bug must not abort the whole scan
            warnings.append(_PassFailure(f"stored-XSS pass failed: {type(exc).__name__}"))
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
        :class:`~webvigil.core.result.CheckError` instead of failing the group. A check keeps
        at most ``FINDINGS_PER_CHECK_CAP`` distinct findings; past it the rest are dropped and
        the scan warns.

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
                        message=_check_error_message(exc),
                        traceback=portable_traceback(exc),
                    )
                )
                return
            kept, cut = _cap_findings(produced)
            if cut:
                context.observations.add_warning(
                    f"check {check_cls.id} reported more than {FINDINGS_PER_CHECK_CAP} findings; "
                    f"the first {FINDINGS_PER_CHECK_CAP} are kept"
                )
            findings.extend(kept)

        async with asyncio.TaskGroup() as group:
            for check_cls in check_types:
                group.create_task(_run_one(check_cls))
        return findings, errors


def _cap_warnings(warnings: Sequence[str]) -> tuple[str, ...]:
    """
    Keep ``WARNINGS_CAP`` warnings of a scan: the first half and the last half of them.

    The passes warn in the order they run, and the scan-level warnings (the deadline, a failed
    pass, the addresses refused) come last, so both ends are kept.

    Args:
        warnings (Sequence[str]): Every warning the scan queued, in order.

    Returns:
        tuple[str, ...]: All of them when they fit; otherwise the first and the last
            ``WARNINGS_CAP // 2``, with one line between them counting those left out.
    """
    if len(warnings) <= WARNINGS_CAP:
        return tuple(warnings)
    half = WARNINGS_CAP // 2
    left_out = len(warnings) - 2 * half
    return (*warnings[:half], f"{left_out} more warnings were not kept", *warnings[-half:])


def _cap_findings(findings: Sequence[Finding]) -> tuple[list[Finding], bool]:
    """
    Keep one check's findings up to ``FINDINGS_PER_CHECK_CAP`` distinct ones, in order.

    Args:
        findings (Sequence[Finding]): What one check returned.

    Returns:
        tuple[list[Finding], bool]: The findings, duplicates removed, cut after the
            ``FINDINGS_PER_CHECK_CAP``-th distinct one; and whether a distinct finding was cut.
    """
    seen: set[str] = set()
    kept: list[Finding] = []
    for finding in findings:
        if finding.fingerprint in seen:
            continue
        if len(kept) >= FINDINGS_PER_CHECK_CAP:
            return kept, True
        seen.add(finding.fingerprint)
        kept.append(finding)
    return kept, False


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


def _check_error_message(exc: Exception) -> str:
    """
    Args:
        exc (Exception): The exception a check raised.

    Returns:
        str: The message of a :class:`~webvigil.core.errors.WebVigilError`, written by this
            project and free of raw failure text, or else the exception's type. The text of any
            other exception may come from a library that quotes a header value or response
            bytes, and the result is shared; the check id, the type and the frames locate it.
    """
    return str(exc) if isinstance(exc, WebVigilError) else type(exc).__name__
