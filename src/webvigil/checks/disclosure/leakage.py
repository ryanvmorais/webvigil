"""
``disclosure.session-id-in-url`` and ``disclosure.private-ip`` — passive leakage checks (spec 013).

Both read only what the crawler already fetched (``ctx.pages``) and issue no
request of their own.

* ``disclosure.session-id-in-url`` (RF-13) flags a session-token- or API-key-
  shaped parameter carried in a URL the **target produced** — a hyperlink, a
  form action, or a redirect ``Location`` — where it leaks into logs, the
  ``Referer`` header, and browser history. The page's own request URL is not
  inspected (it may be a scanner-crafted ``--openapi`` seed); the token value is
  redacted in the evidence.
* ``disclosure.private-ip`` (RF-14) flags an RFC-1918 / loopback / link-local /
  IPv6 unique-local address literal in a response body, capped per page. The
  target's own host is never flagged.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

from selectolax.parser import HTMLParser

from webvigil.checks.base import Check
from webvigil.checks.disclosure import redaction
from webvigil.checks.registry import register
from webvigil.core.context import Page, ScanContext
from webvigil.core.findings import Category, Confidence, EvidenceItem, Finding, Location, Severity

_WSTG_SESSION = (
    "https://owasp.org/www-project-web-security-testing-guide/stable/"
    "4-Web_Application_Security_Testing/06-Session_Management_Testing/"
    "04-Testing_for_Exposed_Session_Variables"
)
_CWE_598 = "https://cwe.mitre.org/data/definitions/598.html"

# Parameter names that specifically carry a session identifier or a credential. Deliberately
# narrow — a bare ``token`` / ``auth`` is too often a one-time reset or verification link.
_SESSION_KEYS = (
    "jsessionid",
    "phpsessid",
    "aspsessionid",
    "asp.net_sessionid",
    "sid",
    "sessionid",
    "session_id",
    "sessiontoken",
    "session_token",
    "authtoken",
    "auth_token",
    "access_token",
    "apikey",
    "api_key",
    "cfid",
    "cftoken",
)
_SESSION_RE = re.compile(
    rf"(?i)[?;&#]({'|'.join(re.escape(k) for k in _SESSION_KEYS)})=([^&;#\s\"'<>]+)"
)

# A full dotted quad in a private / loopback / link-local range, word-bounded so a
# version string like "10.20.30" (three octets) does not match.
_PRIVATE_V4 = re.compile(
    r"\b(?:"
    r"10(?:\.\d{1,3}){3}"
    r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
    r"|192\.168(?:\.\d{1,3}){2}"
    r"|127(?:\.\d{1,3}){3}"
    r"|169\.254(?:\.\d{1,3}){2}"
    r")\b"
)
# IPv6 loopback (``::1``) and unique-local (``fc00::/7`` — first hextet ``fc``/``fd``).
_PRIVATE_V6 = re.compile(r"(?<![:.\w])(?:::1|[fF][cCdD][0-9a-fA-F]{2}:[0-9a-fA-F:]{2,})")

_PER_PAGE_CAP = 10
_CONTEXT_CHARS = 60

_SESSION_DESC = (
    "A session identifier or API key appears in a URL the application handed to the browser. "
    "URLs are written to server and proxy logs, sent in the `Referer` header to other sites, "
    "kept in browser history, and shared when a user copies a link — any of which discloses "
    "the credential."
)
_SESSION_REMEDIATION = (
    "Carry the session identifier in a `Secure`, `HttpOnly` cookie, not the URL. If a token "
    "must be in a link (a one-time action link), make it single-use and short-lived."
)
_PRIVATE_IP_DESC = (
    "A response body exposes an internal IP address (RFC 1918, loopback, or link-local). It "
    "leaks internal network topology that helps an attacker map the environment behind the "
    "application."
)
_PRIVATE_IP_REMEDIATION = (
    "Remove internal addresses from HTML comments, error pages, and API responses. Strip "
    "debugging output before production and configure the framework to return generic errors."
)


def _link_urls(page: Page) -> list[str]:
    """
    Args:
        page (Page): A crawled page.

    Returns:
        list[str]: Every absolute ``<a href>`` / ``<form action>`` URL on the
            page, plus each redirect target the server sent (``history`` hops and
            an out-of-scope ``final_location``).
    """
    urls = [hop.to_url for hop in page.history]
    if page.final_location:
        urls.append(page.final_location)
    if page.ok and page.is_html and page.text:
        for node in HTMLParser(page.text).css("a[href], form[action]"):
            raw = (node.attributes.get("href") or node.attributes.get("action") or "").strip()
            if raw:
                urls.append(urljoin(page.url, raw))
    return urls


@register
class SessionIdInUrlCheck(Check):
    """
    Flags a session identifier or API key carried in a URL the target produced.

    Only hyperlinks, form actions, and redirect targets are inspected — never
    the page's own request URL. The token value is redacted in the evidence.
    """

    id = "disclosure.session-id-in-url"
    name = "Session identifier exposed in a URL"
    category = Category.DISCLOSURE
    default_severity = Severity.MEDIUM
    cwe = (598,)
    references = (_WSTG_SESSION, _CWE_598)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; reads ``ctx.pages``.

        Returns:
            list[Finding]: One finding per distinct ``(key, redacted URL)``.
        """
        findings: list[Finding] = []
        seen: set[str] = set()
        for page in ctx.pages:
            for url in _link_urls(page):
                for match in _SESSION_RE.finditer(url):
                    key = match.group(1)
                    redacted = url.replace(match.group(2), "***", 1)
                    dedup = f"{key.lower()}|{redacted}"
                    if dedup in seen:
                        continue
                    seen.add(dedup)
                    findings.append(
                        self.finding(
                            title=f"Session identifier '{key}' carried in a URL",
                            description=_SESSION_DESC,
                            remediation=_SESSION_REMEDIATION,
                            location=Location(url=page.url),
                            confidence=Confidence.HIGH,
                            dedup_key=dedup,
                            evidence=[
                                EvidenceItem.of("parameter", f"{key}=***"),
                                EvidenceItem.of("URL (redacted)", redacted),
                                EvidenceItem.of("seen on", page.url),
                            ],
                        )
                    )
        return findings


@register
class PrivateIpInBodyCheck(Check):
    """
    Flags an RFC-1918 / loopback / link-local / IPv6 unique-local address in a body.

    The target's own host is never flagged; at most ``_PER_PAGE_CAP`` distinct
    addresses are reported per page.
    """

    id = "disclosure.private-ip"
    name = "Private IP address disclosed in a response body"
    category = Category.DISCLOSURE
    default_severity = Severity.LOW
    cwe = (200,)
    references = ("https://cwe.mitre.org/data/definitions/200.html",)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; reads ``ctx.pages`` and the
                target host.

        Returns:
            list[Finding]: One LOW finding per distinct ``(page URL, address)``.
        """
        own_host = ctx.target.host
        findings: list[Finding] = []
        for page in ctx.pages:
            if not (page.ok and page.text):
                continue
            findings.extend(self._page_findings(page, own_host))
        return findings

    def _page_findings(self, page: Page, own_host: str) -> list[Finding]:
        """
        Args:
            page (Page): A crawled page with a body.
            own_host (str): The scan target host, excluded from matches.

        Returns:
            list[Finding]: The private-IP findings on this page, capped.
        """
        findings: list[Finding] = []
        reported: set[str] = set()
        total = 0
        for pattern in (_PRIVATE_V4, _PRIVATE_V6):
            for match in pattern.finditer(page.text):
                address = match.group(0)
                if address == own_host or address in reported:
                    continue
                total += 1
                if len(reported) >= _PER_PAGE_CAP:
                    continue
                reported.add(address)
                window = page.text[
                    max(0, match.start() - _CONTEXT_CHARS) : match.end() + _CONTEXT_CHARS
                ]
                findings.append(
                    self.finding(
                        title=f"Private IP address {address} disclosed in the response body",
                        description=_PRIVATE_IP_DESC,
                        remediation=_PRIVATE_IP_REMEDIATION,
                        location=Location(url=page.url),
                        confidence=Confidence.MEDIUM,
                        dedup_key=address,
                        evidence=[
                            EvidenceItem.of("address", address),
                            EvidenceItem.of("context", redaction.apply("generic", window)),
                        ],
                    )
                )
        if total > len(reported) and findings:
            note = (
                f"{total} distinct private addresses on this page; the first {len(reported)} shown"
            )
            findings[-1] = findings[-1].model_copy(
                update={"evidence": (*findings[-1].evidence, EvidenceItem.of("note", note))}
            )
        return findings
