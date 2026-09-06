"""HTTP layer: async client wrapper, rate limiting, retries, and the scope guard."""

from __future__ import annotations

from webvigil.http.client import HttpClient, HttpStats, RedirectHop, Response
from webvigil.http.policy import RateLimiter
from webvigil.http.scope_guard import ScopeGuard
from webvigil.http.tls_probe import TlsProbeResult, probe

__all__ = [
    "HttpClient",
    "HttpStats",
    "RateLimiter",
    "RedirectHop",
    "Response",
    "ScopeGuard",
    "TlsProbeResult",
    "probe",
]
