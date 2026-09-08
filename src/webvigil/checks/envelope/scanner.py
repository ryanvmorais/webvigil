"""
The request-envelope pass: poison the ``Host`` header, probe HTTP methods (spec 012).

Runs in the orchestrator, not as a check (like spec 005's ``DisclosureProbe``).
For a bounded sample of the URLs the crawl already found it:

* re-requests each with ``Host`` / ``X-Forwarded-*`` set to an off-scope sentinel
  and looks for the sentinel reflected in an absolute URL / ``Location`` / a
  ``<base>`` or canonical tag, absent from the plain-``GET`` baseline
  (``injection.host-header``, CWE-644);
* sends ``OPTIONS`` and reads ``Allow`` — ``PUT`` / ``DELETE`` / ``PATCH`` /
  ``CONNECT`` advertised on an application route is a finding
  (``http.methods.unsafe``, CWE-650);
* sends one ``TRACE`` — a ``200`` echoing the request is Cross-Site Tracing
  (``http.methods.unsafe``, CWE-693).

It sends only ``GET`` / ``OPTIONS`` / ``TRACE`` — never a state-changing verb.
The sentinel is a header *value* on a request to the in-scope target; WebVigil
never issues a request to it, and a ``Location`` pointing at it is recorded, not
followed (spec 001 RF-04).
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from urllib.parse import urlsplit

from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.core.findings import Confidence, Severity
from webvigil.core.target import Target
from webvigil.crawler.forms import Form
from webvigil.http.client import HttpClient, Response

_HOST_HEADER_ID = "injection.host-header"
_METHODS_ID = "http.methods.unsafe"

_SENTINEL = "webvigil.invalid"
_HOST_VECTORS = ("Host", "X-Forwarded-Host", "X-Forwarded-Server", "X-Host")
_DANGEROUS_VERBS = ("PUT", "DELETE", "PATCH", "CONNECT")

_SENTINEL_IN_URL = re.compile(rf"https?://[^\s\"'<>]*{re.escape(_SENTINEL)}", re.I)
_BASE_CANON = re.compile(
    rf"<base[^>]+href=[\"'][^\"']*{re.escape(_SENTINEL)}"
    rf"|rel=[\"']canonical[\"'][^>]*{re.escape(_SENTINEL)}"
    rf"|property=[\"']og:url[\"'][^>]*{re.escape(_SENTINEL)}",
    re.I,
)
# A reflection whose surrounding text is a reset / verification link is account takeover.
_RESET_CONTEXT = re.compile(r"reset|token|password|confirm|verif|activat|magic", re.I)
# A TRACE echo reflects the whole request, including any [auth] cookie / header WebVigil
# attached (spec 013 RNF-04) — mask those header lines before they enter the evidence.
_SECRET_HEADER_LINE = re.compile(
    r"(?im)^\s*(authorization|cookie|proxy-authorization|x-api-key|x-auth-token|"
    r"api-key|x-amz-security-token|x-csrf-token)\s*:.*$"
)
_STATIC_TYPES = ("image/", "font/", "text/css", "javascript", "application/octet-stream")
_STATIC_EXT = re.compile(r"\.(?:css|js|mjs|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|map|pdf)$", re.I)


@dataclass(frozen=True, slots=True)
class EnvelopeHit:
    """
    One confirmed request-envelope finding, ready for a check to render.

    Attributes:
        check_id (str): The check that consumes this hit
            (``"injection.host-header"`` or ``"http.methods.unsafe"``).
        url (str): The URL the finding is about.
        method (str): The HTTP method that produced it (``GET`` / ``OPTIONS`` /
            ``TRACE``).
        param (str | None): The poisoning header name for a host-header hit;
            ``None`` for a methods hit.
        severity (Severity): Severity for the finding.
        confidence (Confidence): Confidence for the finding.
        title (str): Finding title.
        evidence (tuple[tuple[str, str], ...]): ``(label, content)`` pairs.
    """

    check_id: str
    url: str
    method: str
    param: str | None
    severity: Severity
    confidence: Confidence
    title: str
    evidence: tuple[tuple[str, str], ...]


class EnvelopeScanner:
    """One bounded pass over a URL sample: Host poisoning + an OPTIONS/TRACE probe."""

    def __init__(
        self,
        http: HttpClient,
        target: Target,
        config: ScanConfig,
        pages: tuple[Page, ...],
        forms: tuple[Form, ...],
    ) -> None:
        """
        Args:
            http (HttpClient): The shared, scope-guarded HTTP client.
            target (Target): The normalized target.
            config (ScanConfig): The scan config; reads
                ``injection.envelope_url_sample`` / ``envelope_budget``.
            pages (tuple[Page, ...]): The crawled pages.
            forms (tuple[Form, ...]): The parsed form inventory (form pages are
                sampled first — reset links live there).
        """
        self._http = http
        self._target = target
        self._sample_cap = config.injection.envelope_url_sample
        self._budget = config.injection.envelope_budget
        self._pages = pages
        self._forms = forms
        self._spent = 0
        self.warnings: list[str] = []

    async def run(self) -> list[EnvelopeHit]:
        """
        Sample the URLs, then run the Host-poisoning, OPTIONS and TRACE probes.

        Returns:
            list[EnvelopeHit]: The confirmed hits.
        """
        hits: list[EnvelopeHit] = []
        sample = self._sample_urls()
        for url in sample:
            if self._spent >= self._budget:
                self.warnings.append(
                    f"request-envelope pass stopped at the {self._budget}-request budget"
                )
                break
            baseline = await self._send("GET", url)
            if baseline is None:
                continue
            hits.extend(await self._host_header(url, baseline))
            hits.extend(await self._options(url))
        # TRACE is a server-wide setting, but a route may 405 it; probe a few sampled URLs.
        for url in [self._target.entry_url, *sample][:4]:
            trace = await self._trace(url)
            if trace:
                hits.extend(trace)
                break
        return hits

    def _sample_urls(self) -> list[str]:
        """
        Returns:
            list[str]: The entry URL, then every distinct form-action path, then
                other crawled paths, de-duplicated by path and capped at
                ``envelope_url_sample``.
        """
        seen: set[str] = set()
        ordered: list[str] = []
        candidates = [self._target.entry_url]
        candidates += [form.action for form in self._forms]
        candidates += [page.requested_url for page in self._pages if page.ok]
        for url in candidates:
            path = urlsplit(url).path or "/"
            if path in seen:
                continue
            seen.add(path)
            ordered.append(url)
            if len(ordered) >= self._sample_cap:
                break
        return ordered

    async def _host_header(self, url: str, baseline: Response) -> list[EnvelopeHit]:
        """
        Args:
            url (str): The URL to re-request with a poisoned host.
            baseline (Response): Its plain-``GET`` response — the sentinel must be
                absent from it.

        Returns:
            list[EnvelopeHit]: A single host-header hit (first vector that
                reflects), or empty.
        """
        if self._reflects_sentinel(baseline):
            return []  # the page already echoes the string — not attributable to us
        for vector in _HOST_VECTORS:
            if self._spent >= self._budget:
                break
            resp = await self._send("GET", url, headers={vector: _SENTINEL})
            if resp is None:
                continue
            where = self._sentinel_location(resp)
            if where is None:
                continue
            in_reset = bool(_RESET_CONTEXT.search(self._around_sentinel(resp.text)))
            severity = Severity.HIGH if (where == "Location" or in_reset) else Severity.MEDIUM
            return [
                EnvelopeHit(
                    check_id=_HOST_HEADER_ID,
                    url=url,
                    method="GET",
                    param=vector,
                    severity=severity,
                    confidence=Confidence.HIGH if where == "Location" else Confidence.MEDIUM,
                    title=(
                        f"Host-header injection via the '{vector}' header "
                        f"({where}) at {urlsplit(url).path or '/'}"
                    ),
                    evidence=(
                        ("Poisoned header", f"{vector}: {_SENTINEL}"),
                        ("Reflected in", where),
                        ("Response snippet", self._around_sentinel(resp.text)),
                    ),
                )
            ]
        return []

    async def _options(self, url: str) -> list[EnvelopeHit]:
        """
        Args:
            url (str): The URL to send ``OPTIONS`` to.

        Returns:
            list[EnvelopeHit]: A single methods hit when a dangerous verb is
                advertised on a non-static route, or empty.
        """
        if self._spent >= self._budget:
            return []
        resp = await self._send("OPTIONS", url)
        if resp is None:
            return []
        allow = f"{resp.headers.get('allow', '')} {resp.headers.get('public', '')}".upper()
        advertised = [verb for verb in _DANGEROUS_VERBS if verb in allow]
        if not advertised or self._is_static(url, resp):
            return []
        return [
            EnvelopeHit(
                check_id=_METHODS_ID,
                url=url,
                method="OPTIONS",
                param=None,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                title=f"Unsafe HTTP methods advertised at {urlsplit(url).path or '/'}: "
                + ", ".join(advertised),
                evidence=(
                    ("Allow", resp.headers.get("allow", "(none)")),
                    ("Note", "WebVigil did not verify these are reachable unauthenticated"),
                ),
            )
        ]

    async def _trace(self, url: str) -> list[EnvelopeHit]:
        """
        Args:
            url (str): The URL to send one ``TRACE`` to (the entry URL).

        Returns:
            list[EnvelopeHit]: A single XST hit when ``TRACE`` is enabled and
                echoes the request, or empty.
        """
        if self._spent >= self._budget:
            return []
        token = secrets.token_hex(6)
        resp = await self._send("TRACE", url, headers={"X-Wv-Trace": token})
        if resp is None or resp.status_code != 200:
            return []
        if token not in resp.text and "TRACE " not in resp.text:
            return []
        echoed = _SECRET_HEADER_LINE.sub(r"\1: ***redacted***", resp.text)
        return [
            EnvelopeHit(
                check_id=_METHODS_ID,
                url=url,
                method="TRACE",
                param=None,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title="Cross-Site Tracing (XST): TRACE is enabled and echoes the request",
                evidence=(
                    ("TRACE response", echoed[:200]),
                    (
                        "Impact",
                        "TRACE reflects request headers, defeating HttpOnly cookie protection",
                    ),
                ),
            )
        ]

    async def _send(
        self, method: str, url: str, *, headers: dict[str, str] | None = None
    ) -> Response | None:
        """
        Args:
            method (str): ``GET`` / ``OPTIONS`` / ``TRACE``.
            url (str): The in-scope URL.
            headers (dict[str, str] | None): Extra request headers.

        Returns:
            Response | None: The response, or ``None`` when the budget is spent
                or the request failed.
        """
        if self._spent >= self._budget:
            return None
        self._spent += 1
        try:
            return await self._http.request(method, url, headers=headers, crafted=True)
        except (RequestFailed, OutOfScopeError):
            return None

    def _sentinel_location(self, resp: Response) -> str | None:
        """
        Args:
            resp (Response): The poisoned response.

        Returns:
            str | None: ``"Location"`` / ``"canonical/base tag"`` / ``"body URL"``
                when the sentinel is reflected in a URL-shaped position, else
                ``None``.
        """
        if _SENTINEL in resp.headers.get("location", ""):
            return "Location"
        if _BASE_CANON.search(resp.text):
            return "canonical/base tag"
        if _SENTINEL_IN_URL.search(resp.text):
            return "body URL"
        return None

    def _reflects_sentinel(self, resp: Response) -> bool:
        """
        Args:
            resp (Response): The baseline response.

        Returns:
            bool: ``True`` when the baseline already contains the sentinel (so a
                later match is not attributable to the poisoned header).
        """
        return _SENTINEL in resp.text or _SENTINEL in resp.headers.get("location", "")

    def _around_sentinel(self, text: str, *, span: int = 90) -> str:
        """
        Args:
            text (str): A response body.
            span (int): Characters of context on each side. Defaults to 90.

        Returns:
            str: A trimmed excerpt around the first sentinel occurrence.
        """
        idx = text.lower().find(_SENTINEL)
        if idx == -1:
            return ""
        start = max(0, idx - span)
        end = min(len(text), idx + len(_SENTINEL) + span)
        return (
            ("..." if start else "") + text[start:end].strip() + ("..." if end < len(text) else "")
        )

    def _is_static(self, url: str, resp: Response) -> bool:
        """
        Args:
            url (str): The URL under test.
            resp (Response): Its ``OPTIONS`` response.

        Returns:
            bool: ``True`` when the URL is a static asset (by extension or
                content type) — a dangerous verb there is expected server config.
        """
        if _STATIC_EXT.search(urlsplit(url).path):
            return True
        content_type = resp.headers.get("content-type", "").lower()
        return any(marker in content_type for marker in _STATIC_TYPES)
