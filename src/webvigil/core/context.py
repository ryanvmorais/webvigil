"""The per-scan context handed to every check, plus the ``Page`` value it carries.

``ScanContext`` is the only channel a check has to HTTP and to discovered pages (RF-10). It
holds an ``HttpClient`` by reference; the type is imported only for checking to keep this
module free of a runtime dependency on ``webvigil.http``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx

from webvigil.core.config import ScanConfig
from webvigil.core.target import Target, normalize_url

if TYPE_CHECKING:
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
class ScanContext:
    """Everything a check needs: config, target, the HTTP client, and discovered pages."""

    config: ScanConfig
    target: Target
    http: HttpClient
    pages: tuple[Page, ...]
    entry: Page
    _by_url: dict[str, Page] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        for page in self.pages:
            self._by_url.setdefault(normalize_url(page.url), page)

    def page_for(self, url: str) -> Page | None:
        return self._by_url.get(normalize_url(url))
