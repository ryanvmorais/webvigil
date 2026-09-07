"""
The information-disclosure probe pass (spec 005, RF-04..RF-09, ADR-1, ADR-5).

Runs in the orchestrator, not as a check. Given the crawled pages and the
shared HTTP client it: calibrates the target's "not found" response, requests a
curated catalogue of well-known sensitive paths plus a few derived paths,
content-validates each response, and returns :class:`ProbeHit`\\s the probe-fed
``disclosure.*`` checks turn into findings.

Only in-scope ``GET`` requests, no payloads, no state change — it is Safe
(RNF-03), gated by the ``[disclosure] probe`` toggle rather than the Active-Mode
gate (ADR-6).
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from selectolax.parser import HTMLParser

from webvigil.checks.disclosure import redaction
from webvigil.checks.disclosure.catalogue import (
    ProbeEntry,
    Validator,
    backup_spec,
    build_backup_entry,
)
from webvigil.core.context import Page
from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.core.findings import Confidence, Severity
from webvigil.core.target import Target
from webvigil.http.client import HttpClient, Response

_REQUEST_CAP = 150
_CALIBRATION_PATHS = 3
_MAX_DERIVED_DIRS = 10
_LEN_BAND = 0.15
_LEN_MIN = 256  # bodies shorter than this are too small to fingerprint by length alone

_SOURCEMAP_VALIDATOR = Validator(json_keys=("mappings", "sources", "version"))


@dataclass(frozen=True, slots=True)
class ProbeHit:
    """
    One reachable, content-validated sensitive path (RF-06).

    The body is already redacted — the raw value never leaves this module.

    Attributes:
        family (str): The probe family.
        check_id (str): The probe-fed check that consumes this hit.
        url (str): The full URL that responded.
        path (str): Its path component.
        severity (Severity): Severity for the finding.
        confidence (Confidence): Confidence for the finding.
        title (str): Finding title.
        description (str): Finding description.
        status (int): HTTP status of the response.
        content_type (str): Its ``Content-Type``, or ``"(none)"``.
        redacted_body (str): The response body with secrets removed.
    """

    family: str
    check_id: str
    url: str
    path: str
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    status: int
    content_type: str
    redacted_body: str


@dataclass
class ProbeReport:
    """
    The output of one probe pass.

    Attributes:
        hits (list[ProbeHit]): The confirmed sensitive paths. Defaults to empty.
        paths_probed (int): How many paths were actually requested (after the
            cap). Defaults to 0.
        warnings (list[str]): Non-fatal notices (calibration failure, cap hit).
            Defaults to empty.
    """

    hits: list[ProbeHit] = field(default_factory=list)
    paths_probed: int = 0
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _Soft404:
    """
    The target's learned "not found" shape (RF-06).

    Attributes:
        statuses (frozenset[int]): Status codes the calibration probes returned.
        body_lengths (tuple[int, ...]): Their body lengths, for a fuzzy
            length match.
        shell_hashes (frozenset[str]): SHA-1 of any 2xx "soft 404" bodies.
        inconclusive (bool): ``True`` when calibration could not settle on a
            shape (every probe returned a distinct 2xx body); then
            :meth:`looks_missing` never fires.
    """

    statuses: frozenset[int]
    body_lengths: tuple[int, ...]
    shell_hashes: frozenset[str]
    inconclusive: bool

    def looks_missing(self, status: int, body: str) -> bool:
        """
        Args:
            status (int): A probe response status.
            body (str): Its body.

        Returns:
            bool: ``True`` when the response matches the learned "not found"
                shape and should not be treated as a hit.
        """
        if self.inconclusive:
            return False
        if _hash(body) in self.shell_hashes:
            return True
        if status not in self.statuses:
            return False
        if status >= 400:
            return True
        return any(_close(len(body), base) for base in self.body_lengths)


class DisclosureProbe:
    """Requests the sensitive-path catalogue against one target and validates each response."""

    def __init__(
        self,
        http: HttpClient,
        target: Target,
        catalogue: tuple[ProbeEntry, ...],
        pages: tuple[Page, ...],
    ) -> None:
        """
        Args:
            http (HttpClient): The shared, scope-guarded HTTP client.
            target (Target): The normalized target.
            catalogue (tuple[ProbeEntry, ...]): The expanded probe catalogue.
            pages (tuple[Page, ...]): The crawled pages, mined for referenced
                scripts and discovered directories.
        """
        self._http = http
        self._target = target
        self._catalogue = catalogue
        self._pages = pages

    async def run(self) -> ProbeReport:
        """
        Calibrate, build the target list, probe each path, and collect the hits.

        Returns:
            ProbeReport: The confirmed hits, the probe count, and any warnings.
        """
        report = ProbeReport()
        soft404 = await self._calibrate()
        if soft404.inconclusive:
            report.warnings.append(
                "information-disclosure probing could not calibrate a not-found response; "
                "results rely on content validation only"
            )

        targets = self._targets()
        if len(targets) > _REQUEST_CAP:
            report.warnings.append(
                f"information-disclosure probing stopped at the {_REQUEST_CAP}-request cap "
                f"({len(targets)} candidate paths)"
            )
            targets = targets[:_REQUEST_CAP]
        report.paths_probed = len(targets)

        for entry, url in targets:
            hit = await self._probe(entry, url, soft404)
            if hit is not None:
                report.hits.append(hit)
        return report

    async def _calibrate(self) -> _Soft404:
        """
        Learn the target's "not found" shape from a few random paths.

        Returns:
            _Soft404: The learned shape, or an inconclusive one when the target
                returns a distinct 2xx body for every random path.
        """
        origin = self._target.origin
        probes = [
            f"{origin}/{secrets.token_hex(16)}",
            f"{origin}/{secrets.token_hex(16)}.env",
            f"{origin}/{secrets.token_hex(16)}/",
        ][:_CALIBRATION_PATHS]
        responses = [r for url in probes if (r := await self._get(url)) is not None]
        if not responses:
            return _Soft404(frozenset(), (), frozenset(), inconclusive=True)

        statuses = frozenset(r.status_code for r in responses)
        lengths = tuple(len(r.text) for r in responses)
        shells = frozenset(_hash(r.text) for r in responses if 200 <= r.status_code < 300)
        all_2xx = all(200 <= r.status_code < 300 for r in responses)
        distinct = len({_hash(r.text) for r in responses}) == len(responses)
        inconclusive = all_2xx and distinct and len(responses) > 1
        return _Soft404(statuses, lengths, shells, inconclusive)

    def _targets(self) -> list[tuple[ProbeEntry, str]]:
        """
        Build the de-duplicated list of ``(entry, url)`` pairs to probe.

        Combines the catalogue against the origin, host-label backup names,
        ``.map`` siblings of referenced scripts, and the VCS entries against
        every discovered directory prefix.

        Returns:
            list[tuple[ProbeEntry, str]]: The probe targets, in a stable order.
        """
        origin = self._target.origin
        seen: set[str] = set()
        out: list[tuple[ProbeEntry, str]] = []

        def add(entry: ProbeEntry, url: str) -> None:
            if url not in seen:
                seen.add(url)
                out.append((entry, url))

        for entry in self._catalogue:
            add(entry, f"{origin}/{entry.path}")

        _, suffixes, _ = backup_spec()
        label = self._target.host.split(".")[0]
        for suffix in suffixes:
            add(build_backup_entry(f"{label}{suffix}", suffix), f"{origin}/{label}{suffix}")

        for script_url in self._referenced_scripts():
            add(_sourcemap_entry(), f"{script_url}.map")

        vcs_entries = [entry for entry in self._catalogue if entry.family == "vcs"]
        for prefix in self._discovered_dirs()[:_MAX_DERIVED_DIRS]:
            for entry in vcs_entries:
                add(entry, f"{origin}{prefix}{entry.path}")

        return out

    def _referenced_scripts(self) -> list[str]:
        """
        Returns:
            list[str]: The absolute URLs of in-scope ``<script src>`` ``.js``
                files across the crawled pages, de-duplicated.
        """
        found: list[str] = []
        seen: set[str] = set()
        for page in self._pages:
            if not (page.ok and page.is_html and page.text):
                continue
            for node in HTMLParser(page.text).css("script"):
                src = node.attributes.get("src")
                if not src:
                    continue
                url = urljoin(page.url, src)
                if url.endswith(".js") and url not in seen and self._target.in_scope(url):
                    seen.add(url)
                    found.append(url)
        return found

    def _discovered_dirs(self) -> list[str]:
        """
        Returns:
            list[str]: Every directory prefix (``"/a/"``, ``"/a/b/"``, ...)
                appearing in a crawled URL path, de-duplicated, in discovery
                order.
        """
        prefixes: list[str] = []
        seen: set[str] = set()
        for page in self._pages:
            if not page.ok:
                continue
            path = urlsplit(page.url).path
            segments = [segment for segment in path.split("/") if segment]
            for depth in range(1, len(segments) + 1):
                prefix = "/" + "/".join(segments[:depth]) + "/"
                if prefix != "/" and prefix not in seen:
                    seen.add(prefix)
                    prefixes.append(prefix)
        return prefixes

    async def _probe(self, entry: ProbeEntry, url: str, soft404: _Soft404) -> ProbeHit | None:
        """
        Request one path and decide whether it is a real hit.

        A ``403`` on a directory entry that lists ``403`` in ``ok_status`` is a
        hit at MEDIUM confidence without content validation; otherwise the
        response must pass the entry's validator and not match the soft-404
        shape.

        Args:
            entry (ProbeEntry): The catalogue entry.
            url (str): The resolved URL to request.
            soft404 (_Soft404): The learned "not found" shape.

        Returns:
            ProbeHit | None: The redacted hit, or ``None``.
        """
        response = await self._get(url)
        if response is None or response.status_code not in entry.ok_status:
            return None
        if soft404.looks_missing(response.status_code, response.text):
            return None

        forbidden_dir = response.status_code == 403 and 403 in entry.ok_status
        content_type = response.headers.get("content-type", "") or "(none)"
        if not forbidden_dir and not entry.validator.passes(
            body=response.text, raw=response.content, content_type=content_type
        ):
            return None

        confidence = Confidence.MEDIUM if forbidden_dir else entry.confidence
        return ProbeHit(
            family=entry.family,
            check_id=entry.check_id,
            url=url,
            path=urlsplit(url).path,
            severity=entry.severity,
            confidence=confidence,
            title=entry.title,
            description=entry.description,
            status=response.status_code,
            content_type=content_type,
            redacted_body=redaction.apply(entry.redaction, response.text),
        )

    async def _get(self, url: str) -> Response | None:
        """
        Args:
            url (str): The URL to fetch.

        Returns:
            Response | None: The response, or ``None`` on a transport failure or
                scope refusal.
        """
        try:
            return await self._http.get(url)
        except (RequestFailed, OutOfScopeError):
            return None


def _sourcemap_entry() -> ProbeEntry:
    """
    Returns:
        ProbeEntry: The synthetic entry used for a ``<script>.map`` probe.
    """
    return ProbeEntry(
        path="",
        family="sourcemap",
        check_id="disclosure.sourcemap.exposed",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        title="JavaScript source map exposed",
        description=(
            "A JavaScript source map is reachable over HTTP, exposing the original "
            "(pre-minified) source and its directory layout."
        ),
        validator=_SOURCEMAP_VALIDATOR,
    )


def _hash(body: str) -> str:
    """
    Args:
        body (str): A response body.

    Returns:
        str: Its SHA-1 hex digest.
    """
    return hashlib.sha1(body.encode("utf-8", "ignore")).hexdigest()


def _close(length: int, base: int) -> bool:
    """
    Args:
        length (int): A candidate body length.
        base (int): A calibration body length.

    Returns:
        bool: ``True`` when ``length`` is within ``_LEN_BAND`` of ``base`` and
            ``base`` is large enough to compare by length at all.
    """
    if base < _LEN_MIN:
        return False
    return abs(length - base) <= int(base * _LEN_BAND)
