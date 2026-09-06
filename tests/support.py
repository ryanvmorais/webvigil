"""Value builders shared by the check tests."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

import httpx

from webvigil.core.config import ScanConfig
from webvigil.core.context import Observations, Page, ScanContext
from webvigil.core.findings import (
    Confidence,
    Finding,
    Location,
    ScanMode,
    Severity,
    compute_fingerprint,
)
from webvigil.core.result import CheckError, ScanMetadata, ScanResult
from webvigil.core.target import Scope, Target
from webvigil.core.technology import Technology

_HARDENED_HEADERS: dict[str, str] = {
    "content-security-policy": (
        "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=(), camera=(), microphone=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-embedder-policy": "require-corp",
    "cross-origin-resource-policy": "same-origin",
}


def hardened_headers(**overrides: str) -> dict[str, str]:
    """A response-header set that passes every v0.1 header check."""
    return {**_HARDENED_HEADERS, **overrides}


def make_page(
    *,
    url: str = "https://example.com/",
    status: int = 200,
    headers: dict[str, str] | None = None,
    set_cookies: Sequence[str] = (),
    text: str = "<html><body>ok</body></html>",
    content_type: str = "text/html; charset=utf-8",
) -> Page:
    pairs: list[tuple[str, str]] = [("content-type", content_type)]
    pairs += list((headers or {}).items())
    pairs += [("set-cookie", value) for value in set_cookies]
    return Page(
        requested_url=url,
        url=url,
        status_code=status,
        headers=httpx.Headers(pairs),
        text=text,
        elapsed_ms=1.0,
    )


def make_context(
    page: Page,
    *,
    pages: Sequence[Page] | None = None,
    target_url: str | None = None,
    http: object = None,
    config: ScanConfig | None = None,
    observations: Observations | None = None,
) -> ScanContext:
    resolved_pages = tuple(pages) if pages is not None else (page,)
    return ScanContext(
        config=config or ScanConfig(),
        target=Target.parse(target_url or page.url),
        http=http,  # type: ignore[arg-type]  # header/cookie checks never touch it
        pages=resolved_pages,
        entry=page,
        observations=observations or Observations(),
    )


def make_finding(
    *,
    check_id: str = "http.headers.csp",
    severity: Severity = Severity.MEDIUM,
    url: str = "https://example.com/",
    header: str | None = "Content-Security-Policy",
    param: str | None = None,
    method: str = "GET",
    dedup_key: str = "missing",
    references: tuple[str, ...] = ("https://owasp.org/www-project-secure-headers/",),
) -> Finding:
    location = Location(url=url, header=None if param else header, param=param, method=method)
    return Finding(
        check_id=check_id,
        severity=severity,
        confidence=Confidence.HIGH,
        title=f"{check_id} finding",
        description="Something is wrong.",
        location=location,
        remediation="Fix it.",
        cwe=(693,),
        references=references,
        fingerprint=compute_fingerprint(check_id, location, dedup_key),
    )


def make_result(
    *findings: Finding,
    errors: Sequence[CheckError] = (),
    warnings: Sequence[str] = (),
    authorized_by: str | None = None,
    technologies: Sequence[Technology] = (),
    mode: ScanMode = ScanMode.PASSIVE,
) -> ScanResult:
    findings = tuple(findings)
    metadata = ScanMetadata(
        target="https://example.com/",
        mode=mode,
        scope=Scope.HOST,
        tool_version="0.0.0.test",
        started_at=datetime(2026, 9, 6, 12, 0, tzinfo=UTC),
        finished_at=datetime(2026, 9, 6, 12, 0, 5, tzinfo=UTC),
        pages_scanned=3,
        counts=ScanResult.severity_counts(findings),
        authorized_by=authorized_by,
    )
    return ScanResult(
        metadata=metadata,
        findings=findings,
        technologies=tuple(technologies),
        errors=tuple(errors),
        warnings=tuple(warnings),
    )
