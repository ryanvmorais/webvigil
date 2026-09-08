"""
Value types for the active-injection pass (spec 006, RF-06, RF-07, RF-12).

Internal to ``webvigil.checks.injection``. Only :class:`InjectionHit` leaves the
package — into ``webvigil.core.context`` under ``TYPE_CHECKING`` and into
``checks`` at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from webvigil.core.findings import Confidence, Severity

_Pairs = tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class InjectionPoint:
    """
    One parameter that can carry a payload, plus the request needed to replay it.

    Attributes:
        method (str): ``"GET"`` or ``"POST"``.
        base_url (str): ``scheme://host/path`` — never carries a query.
        param (str): The parameter under test.
        original (str): Its current value.
        params (tuple[tuple[str, str], ...]): The full query (GET) or body
            (POST) set, including ``param``.
        query (tuple[tuple[str, str], ...]): A query string on a POST form's
            action (or an OpenAPI POST operation's query), kept as-is. Defaults
            to empty.
        source (str): ``"query"``, ``"form"``, ``"openapi"`` (a query / body
            parameter of an imported operation), or ``"openapi-path"`` (a path
            segment — ``base_url`` holds the ``{name}`` template). Defaults to
            ``"query"``.
    """

    method: str
    base_url: str
    param: str
    original: str
    params: _Pairs
    query: _Pairs = ()
    source: str = "query"

    @property
    def key(self) -> str:
        """
        Returns:
            str: The dedup identity — the same ``(method, path, param)`` across
                many URLs is one point.
        """
        return f"{self.method} {self.base_url} :: {self.param}"


@dataclass(frozen=True, slots=True)
class Baseline:
    """
    The point's response to its original value — the anchor for differential detection.

    Attributes:
        status (int): Response status.
        raw_body (str): The untouched body, for "signature absent from
            baseline" checks.
        norm_body (str): Whitespace-collapsed, volatile tokens masked — for
            similarity ratios.
        length (int): Length of the raw body.
        elapsed_ms (float): How long the baseline request took, in milliseconds.
    """

    status: int
    raw_body: str
    norm_body: str
    length: int
    elapsed_ms: float


@dataclass(frozen=True, slots=True)
class InjectionHit:
    """
    A confirmed injection, ready for a check to turn into a ``Finding``.

    Attributes:
        kind (str): Detector kind — ``"xss"``, ``"sqli-error"``,
            ``"sqli-boolean"``, ``"sqli-time"``, ``"traversal"``, ``"redirect"``,
            ``"ssrf-metadata"``, ``"ssrf-internal"``. Checks filter on this.
        check_id (str): The check id this hit feeds.
        method (str): HTTP method of the injecting request.
        url (str): The injection point's base URL.
        param (str): The injected parameter.
        severity (Severity): Severity for the finding.
        confidence (Confidence): Confidence for the finding.
        title (str): Finding title.
        payload (str): The payload that worked.
        evidence (tuple[tuple[str, str], ...]): ``(label, content)`` pairs, fed
            to :meth:`~webvigil.core.findings.EvidenceItem.of`.
    """

    kind: str
    check_id: str
    method: str
    url: str
    param: str
    severity: Severity
    confidence: Confidence
    title: str
    payload: str
    evidence: tuple[tuple[str, str], ...]


@dataclass
class ActiveBudget:
    """
    The shared request budget for one Active scan (RF-03, RF-12).

    Attributes:
        request_limit (int): Total crafted requests allowed for the scan.
        per_point_limit (int): Cap on requests spent on a single injection
            point.
        time_based_limit (int): Cap on sleep-inducing requests for the scan.
        spent (int): Requests spent so far. Defaults to 0.
        time_based_spent (int): Sleep-inducing requests spent. Defaults to 0.
        point_spent (int): Requests spent on the current point. Defaults to 0.
    """

    request_limit: int
    per_point_limit: int
    time_based_limit: int
    spent: int = 0
    time_based_spent: int = 0
    point_spent: int = 0

    def exhausted(self) -> bool:
        """
        Returns:
            bool: ``True`` once the per-scan limit leaves no room for another
                request.
        """
        return self.spent >= self.request_limit

    def start_point(self) -> None:
        """Reset the per-point counter before testing a new injection point."""
        self.point_spent = 0

    def take(self, n: int = 1) -> bool:
        """
        Reserve ``n`` requests against the per-scan and per-point caps.

        Args:
            n (int): Number of requests to reserve. Defaults to 1.

        Returns:
            bool: ``True`` when reserved; ``False`` (nothing reserved) when a
                cap would be exceeded.
        """
        if self.spent + n > self.request_limit:
            return False
        if self.point_spent + n > self.per_point_limit:
            return False
        self.spent += n
        self.point_spent += n
        return True

    def take_time_based(self) -> bool:
        """
        Reserve one sleep-inducing request, honouring both the time and general caps.

        Returns:
            bool: ``True`` when reserved, ``False`` otherwise.
        """
        if self.time_based_spent >= self.time_based_limit:
            return False
        if not self.take():
            return False
        self.time_based_spent += 1
        return True

    def take_recrawl(self, n: int = 1) -> bool:
        """
        Reserve ``n`` re-crawl fetches against the per-scan limit only (spec 008, RF-06).

        The per-point cap is a Phase-A concept and must not stop the Phase-B
        re-crawl.

        Args:
            n (int): Number of fetches to reserve. Defaults to 1.

        Returns:
            bool: ``True`` when reserved, ``False`` when the per-scan limit
                would be exceeded.
        """
        if self.spent + n > self.request_limit:
            return False
        self.spent += n
        return True


@dataclass
class InjectionReport:
    """
    The output of ``InjectionScanner.run``.

    Attributes:
        hits (list[InjectionHit]): The confirmed hits. Defaults to empty.
        warnings (list[str]): Non-fatal notices. Defaults to empty.
        points_tested (int): How many injection points were actually tested.
            Defaults to 0.
    """

    hits: list[InjectionHit] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    points_tested: int = 0


@dataclass(frozen=True, slots=True)
class StoredMarker:
    """
    One marker submitted through one injection point during the stored pass (spec 008).

    Attributes:
        token (str): The per-point ``secrets.token_hex`` (without the ``wv``
            prefix), so a marker found on the re-crawl traces back to this
            point.
        point (InjectionPoint): The point the marker was submitted through.
        payloads (tuple[str, ...]): The concrete ``STORED_MARKERS`` strings sent
            (token substituted).
    """

    token: str
    point: InjectionPoint
    payloads: tuple[str, ...]


@dataclass
class StoredXssReport:
    """
    The output of ``StoredXssScanner.run`` (spec 008).

    Attributes:
        hits (list[InjectionHit]): The confirmed stored-XSS hits. Defaults to
            empty.
        warnings (list[str]): Non-fatal notices. Defaults to empty.
        markers_submitted (int): How many markers Phase A submitted. Defaults
            to 0.
        pages_recrawled (int): How many pages Phase B fetched. Defaults to 0.
    """

    hits: list[InjectionHit] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    markers_submitted: int = 0
    pages_recrawled: int = 0
