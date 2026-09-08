"""
``content.sri.missing`` and ``content.mixed`` — passive HTML-subresource checks (spec 013).

Both walk the HTML the crawler already fetched (``ctx.pages``) and issue no
request of their own.

* ``content.sri.missing`` (RF-11) flags a **cross-origin** ``<script>`` /
  ``<link rel=stylesheet>`` / ``<link rel=preload|modulepreload>`` loaded with
  no ``integrity`` attribute — or with ``integrity`` but no ``crossorigin``, so
  the browser cannot run the check. A same-origin subresource is not flagged
  (SRI's value is for third-party CDNs).
* ``content.mixed`` (RF-12) flags an ``https://`` page that references a
  subresource over plain ``http://``. Active content (script / stylesheet /
  frame / form / object / embed) is ``MEDIUM``; passive content (image / media)
  is ``LOW``. A ``//host`` protocol-relative URL inherits ``https`` and is not
  mixed content; an ``http://``-served page is skipped (nothing to downgrade).
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from selectolax.parser import HTMLParser, Node

from webvigil.checks.base import Check
from webvigil.checks.registry import register
from webvigil.core.context import Page, ScanContext
from webvigil.core.findings import Category, Confidence, EvidenceItem, Finding, Location, Severity

_EVIDENCE_TAG_CHARS = 300

_MDN_SRI = "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"
_MDN_MIXED = "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"

# CSS selectors for the subresources SRI applies to, and the resource-URL attribute.
_SRI_SELECTORS = (
    "script[src]",
    'link[rel~="stylesheet"]',
    'link[rel~="preload"]',
    'link[rel~="modulepreload"]',
)

# Mixed-content subresource attributes, split by whether the resource is active
# (executes / styles / frames — MEDIUM) or passive (renders — LOW).
_ACTIVE_MIXED = {
    "script": "src",
    "link": "href",
    "iframe": "src",
    "form": "action",
    "object": "data",
    "embed": "src",
}
_PASSIVE_MIXED = {"img": "src", "video": "src", "audio": "src", "source": "src"}

_SRI_MISSING_DESC = (
    "This page loads a script or stylesheet from another origin without a Subresource "
    "Integrity (`integrity`) attribute. If that third party is compromised — or the "
    "connection to it is tampered with — arbitrary code runs in this page's context. "
    "`integrity` lets the browser reject a resource whose hash does not match."
)
_SRI_NO_CROSSORIGIN_DESC = (
    "This cross-origin subresource has an `integrity` attribute but no `crossorigin` "
    "attribute, so the browser fetches it in no-cors mode and cannot read the response to "
    "verify the hash — the integrity check silently does not run."
)
_SRI_REMEDIATION = (
    'Add `integrity="sha384-..."` and `crossorigin="anonymous"` to every cross-origin '
    "`<script>` and `<link rel=stylesheet>`. Pin the exact version of the resource so the "
    "hash stays valid, or self-host it."
)
_MIXED_DESC = (
    "An HTTPS page references this resource over plain HTTP. The browser either blocks it "
    "(active content) or loads it over an interceptable channel (passive content), and the "
    "page loses its secure-context guarantees."
)
_MIXED_REMEDIATION = (
    "Serve every subresource over HTTPS. Use protocol-relative or scheme-relative URLs, or "
    "add a `Content-Security-Policy: upgrade-insecure-requests` directive as a stopgap."
)


def _origin(url: str) -> tuple[str, str]:
    """
    Args:
        url (str): An absolute URL.

    Returns:
        tuple[str, str]: Its ``(scheme, netloc)``, lower-cased — the origin key.
    """
    parts = urlsplit(url)
    return parts.scheme.lower(), parts.netloc.lower()


def _tag_html(node: Node) -> str:
    """
    Args:
        node (Node): A parsed element.

    Returns:
        str: The element's serialized HTML, trimmed for evidence.
    """
    html = node.html or ""
    return html[:_EVIDENCE_TAG_CHARS]


@register
class SriMissingCheck(Check):
    """
    Flags a cross-origin ``<script>`` / ``<link>`` subresource loaded without SRI.

    Same-origin subresources are ignored. A subresource with ``integrity`` but
    no ``crossorigin`` is flagged separately — the check cannot run without it.
    """

    id = "content.sri.missing"
    name = "Subresource Integrity missing on a cross-origin resource"
    category = Category.CONTENT
    default_severity = Severity.MEDIUM
    cwe = (353, 1104)
    references = (_MDN_SRI,)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; reads ``ctx.pages``.

        Returns:
            list[Finding]: One finding per distinct cross-origin resource URL
                that is missing ``integrity`` (or ``crossorigin``).
        """
        findings: list[Finding] = []
        seen: set[str] = set()
        for page in ctx.pages:
            if not (page.ok and page.is_html and page.text):
                continue
            tree = HTMLParser(page.text)
            for selector in _SRI_SELECTORS:
                for node in tree.css(selector):
                    finding = self._inspect(page, node, seen)
                    if finding is not None:
                        findings.append(finding)
        return findings

    def _inspect(self, page: Page, node: Node, seen: set[str]) -> Finding | None:
        """
        Args:
            page (Page): The page the node is on.
            node (Node): A ``<script>`` or ``<link>`` element.
            seen (set[str]): Resource URLs already reported, updated in place.

        Returns:
            Finding | None: A finding when the subresource is cross-origin and
                lacks ``integrity`` / ``crossorigin``; ``None`` otherwise.
        """
        raw = node.attributes.get("src") or node.attributes.get("href")
        if not raw:
            return None
        resource = urljoin(page.url, raw.strip())
        if not resource.lower().startswith(("http://", "https://")):
            return None
        if _origin(resource) == _origin(page.url) or resource in seen:
            return None

        has_integrity = "integrity" in node.attributes
        has_crossorigin = "crossorigin" in node.attributes
        if has_integrity and has_crossorigin:
            return None
        seen.add(resource)

        if not has_integrity:
            title = f"Cross-origin resource loaded without Subresource Integrity: {resource}"
            description = _SRI_MISSING_DESC
        else:
            title = f"Subresource Integrity present but 'crossorigin' missing: {resource}"
            description = _SRI_NO_CROSSORIGIN_DESC
        return self.finding(
            title=title,
            description=description,
            remediation=_SRI_REMEDIATION,
            location=Location(url=page.url),
            confidence=Confidence.HIGH,
            dedup_key=resource,
            evidence=[
                EvidenceItem.of("element", _tag_html(node)),
                EvidenceItem.of("resource", resource),
            ],
        )


@register
class MixedContentCheck(Check):
    """
    Flags an ``https://`` page that references a subresource over plain ``http://``.

    Active content (script, stylesheet, frame, form, object, embed) is
    ``MEDIUM``; passive content (image, media) is ``LOW``. A protocol-relative
    ``//host`` URL is not mixed content.
    """

    id = "content.mixed"
    name = "Mixed content: an HTTPS page loads a resource over HTTP"
    category = Category.CONTENT
    default_severity = Severity.MEDIUM
    cwe = (319,)
    references = (_MDN_MIXED,)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; reads ``ctx.pages``.

        Returns:
            list[Finding]: One finding per distinct ``http://`` subresource URL
                on an HTTPS page.
        """
        findings: list[Finding] = []
        seen: set[str] = set()
        for page in ctx.pages:
            if not (page.ok and page.is_html and page.text):
                continue
            if not page.url.lower().startswith("https://"):
                continue
            findings.extend(self._page_findings(page, seen))
        return findings

    def _page_findings(self, page: Page, seen: set[str]) -> list[Finding]:
        """
        Args:
            page (Page): An HTTPS page.
            seen (set[str]): ``http://`` URLs already reported, updated in place.

        Returns:
            list[Finding]: The mixed-content findings on this page.
        """
        tree = HTMLParser(page.text)
        findings: list[Finding] = []
        for active, attrs in ((True, _ACTIVE_MIXED), (False, _PASSIVE_MIXED)):
            for tag, attr in attrs.items():
                for node in tree.css(f"{tag}[{attr}]"):
                    raw = (node.attributes.get(attr) or "").strip()
                    if not raw:
                        continue
                    resource = urljoin(page.url, raw)
                    if not resource.lower().startswith("http://") or resource in seen:
                        continue
                    seen.add(resource)
                    findings.append(self._finding(page, tag, node, resource, active))
        return findings

    def _finding(self, page: Page, tag: str, node: Node, resource: str, active: bool) -> Finding:
        """
        Args:
            page (Page): The HTTPS page.
            tag (str): The element tag name.
            node (Node): The referencing element.
            resource (str): The resolved ``http://`` URL.
            active (bool): Whether the resource is active (executes / styles /
                frames) rather than passive.

        Returns:
            Finding: MEDIUM for active content, LOW for passive.
        """
        kind = "Active" if active else "Passive"
        return self.finding(
            title=f"{kind} mixed content: <{tag}> loads {resource} over HTTP",
            description=_MIXED_DESC,
            remediation=_MIXED_REMEDIATION,
            location=Location(url=page.url),
            severity=Severity.MEDIUM if active else Severity.LOW,
            confidence=Confidence.HIGH,
            dedup_key=resource,
            evidence=[
                EvidenceItem.of("element", _tag_html(node)),
                EvidenceItem.of("resource", resource),
            ],
        )
