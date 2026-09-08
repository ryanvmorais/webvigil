"""
The per-scan context handed to every check, plus the ``Page`` value it carries.

:class:`ScanContext` is the only channel a check has to HTTP and to discovered
pages (RF-10). It holds an ``HttpClient`` by reference; the type is imported
only for checking, to keep this module free of a runtime dependency on
``webvigil.http``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx

from webvigil.core.config import ScanConfig
from webvigil.core.target import Target, normalize_url
from webvigil.core.technology import DetectionMethod, Technology

if TYPE_CHECKING:
    from webvigil.checks.deps.advisories import Advisory
    from webvigil.checks.disclosure.probe import ProbeHit
    from webvigil.checks.envelope.scanner import EnvelopeHit
    from webvigil.checks.injection.models import InjectionHit
    from webvigil.crawler.forms import Form
    from webvigil.http.client import HttpClient, RedirectHop, Response


@dataclass(frozen=True, slots=True)
class Page:
    """
    A single fetched URL and its response (after in-scope redirects), or a fetch error.

    Attributes:
        requested_url (str): The URL the crawler asked for.
        url (str): The final URL after in-scope redirects.
        status_code (int): HTTP status of the final response, or ``0`` on a
            fetch error.
        headers (httpx.Headers): Response headers of the final response.
        text (str): Response body, decoded.
        elapsed_ms (float): Wall-clock time for the fetch, in milliseconds.
        history (tuple[RedirectHop, ...]): Redirect hops followed to reach
            ``url``. Defaults to empty.
        redirected_out_of_scope (bool): ``True`` when a redirect pointed
            outside scope and was not followed. Defaults to ``False``.
        final_location (str | None): The out-of-scope ``Location`` that was
            not followed, when applicable.
        error (str | None): Description of the transport failure, or ``None``
            on success.
    """

    requested_url: str
    url: str
    status_code: int
    headers: httpx.Headers
    text: str
    elapsed_ms: float
    history: tuple[RedirectHop, ...] = ()
    redirected_out_of_scope: bool = False
    final_location: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        """
        Returns:
            bool: ``True`` when the page was fetched without a transport error.
        """
        return self.error is None

    @property
    def is_html(self) -> bool:
        """
        Returns:
            bool: ``True`` when the response ``Content-Type`` names HTML.
        """
        return "html" in self.headers.get("content-type", "").lower()

    @classmethod
    def from_response(cls, response: Response) -> Page:
        """
        Build a page from a successful HTTP response.

        Args:
            response (Response): The response returned by the HTTP client.

        Returns:
            Page: A page carrying the response's final URL, status, headers,
                body, and redirect history.
        """
        return cls(
            requested_url=response.requested_url,
            url=response.url,
            status_code=response.status_code,
            headers=response.headers,
            text=response.text,
            elapsed_ms=response.elapsed_ms,
            history=response.history,
            redirected_out_of_scope=response.redirected_out_of_scope,
            final_location=response.final_location,
        )

    @classmethod
    def failed(cls, url: str, error: str) -> Page:
        """
        Build a placeholder page for a URL that could not be fetched.

        Args:
            url (str): The URL that failed.
            error (str): Description of the transport failure.

        Returns:
            Page: A page with ``status_code`` ``0``, an empty body, and
                ``error`` set.
        """
        return cls(
            requested_url=url,
            url=url,
            status_code=0,
            headers=httpx.Headers(),
            text="",
            elapsed_ms=0.0,
            error=error,
        )


@dataclass(frozen=True, slots=True)
class Detection:
    """
    One library identified by the dependency fingerprint pass (spec 004, RF-01).

    Attributes:
        name (str): Library name as Retire.js knows it.
        version (str | None): Detected version, or ``None`` when only the
            library could be identified.
        method (DetectionMethod): How the library (and version) was found.
        source_url (str): URL of the resource the detection came from.
        marker (str): The raw filename, banner line, or hash that matched —
            becomes evidence on the resulting finding.
    """

    name: str
    version: str | None
    method: DetectionMethod
    source_url: str
    marker: str


@dataclass(slots=True)
class Observations:
    """
    A side channel for structured output a check produces besides its findings (ADR-2).

    The dependency fingerprint pass fills ``detections`` once, the OSV lookup
    pass fills ``osv_advisories`` once (spec 010, empty unless ``[deps]
    osv_online`` is on), the disclosure probe pass fills ``probe_hits`` once,
    and the active-injection pass fills ``injection_hits`` once (all set by the
    orchestrator); the ``deps.*`` checks call :meth:`add_technology` /
    :meth:`add_warning` and read ``osv_advisories``, the probe-fed
    ``disclosure.*`` checks read ``probe_hits``, and the ``injection.*`` checks
    read ``injection_hits``. Mutated only from synchronous check code, so a
    plain dict/list is safe under the single-threaded event loop.

    Attributes:
        detections (tuple[Detection, ...]): Libraries found by the fingerprint
            pass. Defaults to empty.
        osv_advisories (Mapping[tuple[str, str], tuple[Advisory, ...]]):
            ``(library name, version)`` -> advisories from OSV.dev (spec 010,
            RF-08). Empty unless ``[deps] osv_online`` is on.
        probe_hits (tuple[ProbeHit, ...]): Sensitive paths the disclosure probe
            reached. Defaults to empty.
        injection_hits (tuple[InjectionHit, ...]): Confirmed hits from the
            active-injection and stored-XSS passes. Defaults to empty.
        envelope_hits (tuple[EnvelopeHit, ...]): Confirmed hits from the
            request-envelope pass (host-header injection, unsafe HTTP methods —
            spec 012). Defaults to empty.
        warnings (list[str]): Non-fatal notices a check wants surfaced on the
            result. Defaults to empty.
    """

    detections: tuple[Detection, ...] = ()
    osv_advisories: Mapping[tuple[str, str], tuple[Advisory, ...]] = field(default_factory=dict)
    probe_hits: tuple[ProbeHit, ...] = ()
    injection_hits: tuple[InjectionHit, ...] = ()
    envelope_hits: tuple[EnvelopeHit, ...] = ()
    _technologies: dict[tuple[str, str | None], Technology] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def add_technology(self, technology: Technology) -> None:
        """
        Record a detected technology, keeping the first entry per (name, version).

        Args:
            technology (Technology): The technology to add.
        """
        self._technologies.setdefault((technology.name, technology.version), technology)

    def add_warning(self, message: str) -> None:
        """
        Queue a non-fatal notice to surface on the scan result.

        Args:
            message (str): The warning text.
        """
        self.warnings.append(message)

    @property
    def technologies(self) -> tuple[Technology, ...]:
        """
        Returns:
            tuple[Technology, ...]: The recorded technologies, sorted by name
                then version.
        """
        return tuple(sorted(self._technologies.values(), key=lambda t: (t.name, t.version or "")))


@dataclass(frozen=True, slots=True)
class ScanContext:
    """
    Everything a check needs to run.

    Attributes:
        config (ScanConfig): The resolved configuration for this scan.
        target (Target): The normalized target and its scope rule.
        http (HttpClient): The shared, scope-guarded HTTP client.
        pages (tuple[Page, ...]): Every page the crawler discovered.
        entry (Page): The entry page (``pages[0]``).
        forms (tuple[Form, ...]): The parsed ``<form>`` inventory (spec 007),
            read-only during the check run. Defaults to empty.
        observations (Observations): The side channel for structured output;
            excluded from equality.
    """

    config: ScanConfig
    target: Target
    http: HttpClient
    pages: tuple[Page, ...]
    entry: Page
    forms: tuple[Form, ...] = ()
    observations: Observations = field(default_factory=Observations, compare=False)
    _by_url: dict[str, Page] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        """Index the pages by normalized URL for :meth:`page_for`."""
        for page in self.pages:
            self._by_url.setdefault(normalize_url(page.url), page)

    def page_for(self, url: str) -> Page | None:
        """
        Look up an already-fetched page by URL.

        Args:
            url (str): The URL to resolve; normalized before lookup.

        Returns:
            Page | None: The matching page, or ``None`` when the crawler never
                fetched it.
        """
        return self._by_url.get(normalize_url(url))
