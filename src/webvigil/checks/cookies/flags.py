"""Cookie-flag check: Secure / HttpOnly / SameSite / prefixes (RF-18)."""

from __future__ import annotations

from webvigil.checks.base import Check
from webvigil.checks.headers._parsing import is_https, parse_set_cookie
from webvigil.checks.registry import register
from webvigil.core.context import Page, ScanContext
from webvigil.core.findings import Category, EvidenceItem, Finding, Location, Severity


@register
class CookieFlagsCheck(Check):
    id = "http.cookies.flags"
    name = "Cookie flag weaknesses"
    category = Category.COOKIES
    default_severity = Severity.MEDIUM
    cwe = (614, 1004)
    references = ("https://owasp.org/www-community/controls/SecureCookieAttribute",)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for page in ctx.pages:
            if not page.ok:
                continue
            for raw in page.headers.get_list("set-cookie"):
                findings.extend(self._inspect(page, raw))
        return findings

    def _inspect(self, page: Page, raw: str) -> list[Finding]:
        name, attrs = parse_set_cookie(raw)
        if not name:
            return []

        secure = attrs.get("secure") is True
        http_only = attrs.get("httponly") is True
        same_site = str(attrs.get("samesite", "")).lower()
        path = str(attrs.get("path", "")) or "/"
        has_domain = "domain" in attrs
        on_https = is_https(page.url)
        evidence = [EvidenceItem.of("Set-Cookie", raw)]
        location = Location(url=page.url, cookie=name)
        out: list[Finding] = []

        if on_https and not secure:
            out.append(
                self._finding(
                    location,
                    evidence,
                    "no-secure",
                    Severity.MEDIUM,
                    f"Cookie '{name}' is set without the Secure attribute",
                    "The cookie can be sent over plaintext HTTP and intercepted.",
                    "Add the Secure attribute so the cookie is only sent over HTTPS.",
                )
            )
        if not http_only:
            out.append(
                self._finding(
                    location,
                    evidence,
                    "no-httponly",
                    Severity.LOW,
                    f"Cookie '{name}' is set without the HttpOnly attribute",
                    "The cookie is readable from JavaScript, so an XSS flaw can exfiltrate it.",
                    "Add the HttpOnly attribute unless the cookie must be read by scripts.",
                )
            )
        if same_site == "none" and not secure:
            out.append(
                self._finding(
                    location,
                    evidence,
                    "samesite-none-insecure",
                    Severity.MEDIUM,
                    f"Cookie '{name}' uses SameSite=None without Secure",
                    "Browsers reject SameSite=None cookies that are not also Secure.",
                    "Add the Secure attribute, or use SameSite=Lax/Strict.",
                )
            )
        if same_site == "":
            out.append(
                self._finding(
                    location,
                    evidence,
                    "samesite-unset",
                    Severity.LOW,
                    f"Cookie '{name}' does not set SameSite",
                    "Without SameSite the cookie is exposed to cross-site request forgery.",
                    "Set SameSite=Lax (or Strict) explicitly.",
                )
            )
        if name.startswith("__Host-") and (has_domain or path != "/" or not secure):
            out.append(
                self._finding(
                    location,
                    evidence,
                    "host-prefix-violation",
                    Severity.MEDIUM,
                    f"Cookie '{name}' violates the __Host- prefix requirements",
                    "A __Host- cookie must be Secure, have Path=/, and set no Domain.",
                    "Send it as Secure, Path=/, with no Domain attribute — or drop the prefix.",
                )
            )
        elif name.startswith("__Secure-") and not secure:
            out.append(
                self._finding(
                    location,
                    evidence,
                    "secure-prefix-violation",
                    Severity.MEDIUM,
                    f"Cookie '{name}' has the __Secure- prefix but is not Secure",
                    "Browsers reject __Secure- cookies that lack the Secure attribute.",
                    "Add the Secure attribute or drop the prefix.",
                )
            )
        return out

    def _finding(
        self,
        location: Location,
        evidence: list[EvidenceItem],
        dedup_suffix: str,
        severity: Severity,
        title: str,
        description: str,
        remediation: str,
    ) -> Finding:
        return self.finding(
            title=title,
            description=description,
            remediation=remediation,
            location=location,
            severity=severity,
            dedup_key=f"{location.cookie}:{dedup_suffix}",
            evidence=evidence,
        )
