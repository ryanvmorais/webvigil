"""Value types for the active-injection pass (spec 006, RF-06, RF-07, RF-12).

Internal to ``webvigil.checks.injection``. Only :class:`InjectionHit` leaves the package —
into ``webvigil.core.context`` under ``TYPE_CHECKING`` and into ``checks`` at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from webvigil.core.findings import Confidence, Severity

_Pairs = tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class InjectionPoint:
    """One parameter that can carry a payload, plus the request needed to replay it."""

    method: str  # "GET" | "POST"
    base_url: str  # scheme://host/path — never carries a query
    param: str  # the parameter under test
    original: str  # its current value
    params: _Pairs  # the full query (GET) or body (POST) set, including ``param``
    query: _Pairs = ()  # a query string on a POST form's action, kept as-is
    source: str = "query"  # "query" | "form"

    @property
    def key(self) -> str:
        """Dedup identity — the same (method, path, param) across many URLs is one point."""
        return f"{self.method} {self.base_url} :: {self.param}"


@dataclass(frozen=True, slots=True)
class Baseline:
    """The point's response to its original value — the anchor for differential detection."""

    status: int
    raw_body: str  # untouched — for "signature absent from baseline"
    norm_body: str  # whitespace-collapsed, volatile tokens masked — for similarity
    length: int
    elapsed_ms: float


@dataclass(frozen=True, slots=True)
class InjectionHit:
    """A confirmed injection, ready for a check to turn into a :class:`Finding`."""

    kind: str  # "xss" | "sqli-error" | "sqli-boolean" | "sqli-time" | "traversal" | "redirect"
    check_id: str
    method: str
    url: str
    param: str
    severity: Severity
    confidence: Confidence
    title: str
    payload: str
    evidence: tuple[tuple[str, str], ...]  # (label, content) pairs → EvidenceItem.of


@dataclass
class ActiveBudget:
    """The shared request budget for one Active scan (RF-03, RF-12)."""

    request_limit: int
    per_point_limit: int
    time_based_limit: int
    spent: int = 0
    time_based_spent: int = 0
    point_spent: int = 0

    def exhausted(self) -> bool:
        """True once the per-scan limit leaves no room for another request."""
        return self.spent >= self.request_limit

    def start_point(self) -> None:
        self.point_spent = 0

    def take(self, n: int = 1) -> bool:
        """Reserve ``n`` requests; return False (without reserving) when a cap is reached."""
        if self.spent + n > self.request_limit:
            return False
        if self.point_spent + n > self.per_point_limit:
            return False
        self.spent += n
        self.point_spent += n
        return True

    def take_time_based(self) -> bool:
        """Reserve one sleep-inducing request, honouring both the time and general caps."""
        if self.time_based_spent >= self.time_based_limit:
            return False
        if not self.take():
            return False
        self.time_based_spent += 1
        return True

    def take_recrawl(self, n: int = 1) -> bool:
        """Reserve ``n`` re-crawl fetches against the per-scan limit only (spec 008, RF-06).

        The per-point cap is a Phase-A concept and must not stop the Phase-B re-crawl.
        """
        if self.spent + n > self.request_limit:
            return False
        self.spent += n
        return True


@dataclass
class InjectionReport:
    """The output of ``InjectionScanner.run``."""

    hits: list[InjectionHit] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    points_tested: int = 0


@dataclass(frozen=True, slots=True)
class StoredMarker:
    """One marker submitted through one injection point during the stored pass (spec 008)."""

    token: str  # the per-point secrets.token_hex (without the "wv" prefix)
    point: InjectionPoint
    payloads: tuple[str, ...]  # the concrete STORED_MARKERS strings sent (token substituted)


@dataclass
class StoredXssReport:
    """The output of ``StoredXssScanner.run`` (spec 008)."""

    hits: list[InjectionHit] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    markers_submitted: int = 0
    pages_recrawled: int = 0
