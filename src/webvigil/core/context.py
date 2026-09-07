"""The per-scan context handed to every check, plus the ``Page`` value it carries.

``ScanContext`` is the only channel a check has to HTTP and to discovered pages (RF-10). It
holds an ``HttpClient`` by reference; the type is imported only for checking to keep this
module free of a runtime dependency on ``webvigil.http``.
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
    from webvigil.checks.injection.models import InjectionHit
    from webvigil.crawler.forms import Form
    from webvigil.http.client import HttpClient, RedirectHop, Response


@dataclass(frozen=True, slots=True)
class Page:
    """A single fetched URL and its response (after in-scope redirects), or a fetch error."""

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
        return self.error is None

    @property
    def is_html(self) -> bool:
        return "html" in self.headers.get("content-type", "").lower()

    @classmethod
    def from_response(cls, response: Response) -> Page:
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
    """One library identified by the dependency fingerprint pass (spec 004, RF-01)."""

    name: str
    version: str | None
    method: DetectionMethod
    source_url: str
    marker: str  # the raw filename / banner line / hash that matched — becomes evidence


@dataclass(slots=True)
class Observations:
    """A side channel for structured output a check produces besides its findings (ADR-2).

    The dependency fingerprint pass fills ``detections`` once, the OSV lookup pass fills
    ``osv_advisories`` once (spec 010, empty unless ``[deps] osv_online`` is on), the
    disclosure probe pass fills ``probe_hits`` once, and the active-injection pass fills
    ``injection_hits`` once (all set by the orchestrator); the ``deps.*`` checks call
    :meth:`add_technology` / :meth:`add_warning` and read ``osv_advisories``, the probe-fed
    ``disclosure.*`` checks read ``probe_hits``, and the ``injection.*`` checks read
    ``injection_hits``. Mutated only from synchronous check code, so a plain dict/list is
    safe under the single-threaded event loop.
    """

    detections: tuple[Detection, ...] = ()
    # (webvigil library name, version) -> advisories from OSV.dev (spec 010, RF-08).
    osv_advisories: Mapping[tuple[str, str], tuple[Advisory, ...]] = field(default_factory=dict)
    probe_hits: tuple[ProbeHit, ...] = ()
    injection_hits: tuple[InjectionHit, ...] = ()
    _technologies: dict[tuple[str, str | None], Technology] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def add_technology(self, technology: Technology) -> None:
        self._technologies.setdefault((technology.name, technology.version), technology)

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    @property
    def technologies(self) -> tuple[Technology, ...]:
        return tuple(sorted(self._technologies.values(), key=lambda t: (t.name, t.version or "")))


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Everything a check needs: config, target, the HTTP client, discovered pages, and the
    parsed ``<form>`` inventory (spec 007 — ``forms``, read-only during the check run)."""

    config: ScanConfig
    target: Target
    http: HttpClient
    pages: tuple[Page, ...]
    entry: Page
    forms: tuple[Form, ...] = ()
    observations: Observations = field(default_factory=Observations, compare=False)
    _by_url: dict[str, Page] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        for page in self.pages:
            self._by_url.setdefault(normalize_url(page.url), page)

    def page_for(self, url: str) -> Page | None:
        return self._by_url.get(normalize_url(url))
