"""
The active-injection checks: turn ``InjectionHit``s into findings (RF-08..RF-11).

None of them issues a request — ``engine.InjectionScanner`` and the stored-XSS
pass (an orchestrator pass each) have already run and left their hits on
``ctx.observations.injection_hits``. Each check filters by ``kind`` and pulls
its description / remediation / references from the module-level dicts keyed on
that kind.
"""

from __future__ import annotations

from typing import ClassVar

from webvigil.checks.base import Check
from webvigil.checks.registry import register
from webvigil.core.context import ScanContext
from webvigil.core.findings import Category, EvidenceItem, Finding, Location, ScanMode, Severity

_OWASP = "https://owasp.org/www-community"

_DESCRIPTION: dict[str, str] = {
    "xss": (
        "A value supplied in this parameter is reflected in the response with its "
        "HTML-significant characters intact, in a context where a browser would execute it. "
        "An attacker can craft a link that runs arbitrary JavaScript in a victim's session."
    ),
    "sqli-error": (
        "A value supplied in this parameter reaches a SQL query unsanitised: a broken quote "
        "produced a database error in the response. The query can likely be rewritten to "
        "read or modify arbitrary data."
    ),
    "sqli-boolean": (
        "A value supplied in this parameter changes the result set of a SQL query in a way "
        "that tracks a true/false condition (blind SQL injection). Data can be extracted one "
        "bit at a time even though the response shows no error."
    ),
    "sqli-time": (
        "A value supplied in this parameter can make the database sleep for a chosen number "
        "of seconds (time-based blind SQL injection). The query is attacker-controlled even "
        "though the response body never changes."
    ),
    "traversal": (
        "A value supplied in this parameter is used to build a filesystem path without "
        "containment: a '../' sequence reached a file outside the intended directory "
        "(a known system file was returned)."
    ),
    "redirect": (
        "A value supplied in this parameter controls the redirect target and an off-site URL "
        "was honoured. Attackers use this for convincing phishing links and, with OAuth-style "
        "flows, for token theft."
    ),
    "xss-stored": (
        "A value supplied in this parameter is stored by the application and later rendered in "
        "another page's HTML with its markup intact, in a context where a browser would execute "
        "it. The payload runs for every user who views that page — no phishing link required."
    ),
    "ssrf-metadata": (
        "A URL supplied in this parameter is fetched by the server, and the request reached the "
        "cloud instance metadata service. That endpoint exposes instance details and, on most "
        "providers, temporary IAM credentials — full account compromise is a common next step."
    ),
    "ssrf-internal": (
        "A URL supplied in this parameter is fetched by the server. WebVigil reached a loopback "
        "or internal-only resource, read a local file via file://, or confirmed the outbound "
        "request from a connection error naming the injected URL. An attacker can pivot to "
        "internal services that trust the application's network position."
    ),
    "cmdi": (
        "A value supplied in this parameter is passed to an operating-system shell. WebVigil "
        "appended a shell command and the server executed it — proved by a computed value in "
        "the response that reflection alone could not produce, or by an attacker-controlled "
        "response delay. This is remote code execution."
    ),
    "ssti": (
        "A value supplied in this parameter is concatenated into server-side template source "
        "rather than passed as template data. WebVigil injected a template expression and the "
        "engine evaluated it (an arithmetic expression returned its result). Most template "
        "engines expose enough of the host language to reach remote code execution."
    ),
    "crlf": (
        "A value supplied in this parameter is written into a response header without stripping "
        "carriage-return / line-feed. WebVigil injected its own header line (or, with a double "
        "CRLF, a whole response body) and the server sent it back. This enables response "
        "splitting, Set-Cookie injection / session fixation, and cache poisoning."
    ),
    "xxe": (
        "An endpoint parsed a WebVigil-supplied XML body with an entity-resolving parser: an "
        "external-entity declaration was expanded (a local file was read) or produced a parser "
        "error naming the entity. XXE reads local files and, via SYSTEM URLs, can reach "
        "internal services (SSRF)."
    ),
    "ldap": (
        "A value supplied in this parameter is spliced into an LDAP search filter without "
        "escaping. WebVigil either drew a filter-parser error or widened the result set with an "
        "always-true filter. An attacker can read directory entries they should not see or "
        "bypass an LDAP-backed authentication check."
    ),
    "xpath": (
        "A value supplied in this parameter is concatenated into an XPath expression evaluated "
        "over an XML document. WebVigil either drew an expression-parser error or flipped a "
        "true/false condition (blind XPath injection). The whole document can be extracted one "
        "node at a time."
    ),
    "ssi": (
        "A value supplied in this parameter is reflected into a page that a server-side include "
        "(or ESI) processor then evaluates. WebVigil injected an #echo / <esi:vars> directive "
        "and the server ran it. SSI injection commonly escalates to file disclosure and, where "
        "#exec is enabled, to command execution."
    ),
}

_SQLI_FIX = (
    "Use parameterised queries / prepared statements; never build a SQL statement by "
    "concatenating strings. An ORM's query builder is fine as long as raw fragments are "
    "not interpolated."
)

_SSRF_FIX = (
    "Do not fetch user-supplied URLs directly. Resolve the host and reject any address that "
    "is loopback, link-local (169.254.0.0/16), private (RFC 1918), or otherwise internal — "
    "after DNS resolution, and again on every redirect. Allow-list the schemes (https only) "
    "and the destination hosts. On AWS, require IMDSv2 and set the metadata hop limit to 1."
)

_REMEDIATION: dict[str, str] = {
    "xss": (
        "Context-encode all untrusted output (HTML entity, attribute, JavaScript-string, or "
        "URL encoding as appropriate); prefer a templating engine that auto-escapes. Add a "
        "Content-Security-Policy as defence in depth."
    ),
    "sqli-error": _SQLI_FIX,
    "sqli-boolean": _SQLI_FIX,
    "sqli-time": _SQLI_FIX,
    "traversal": (
        "Resolve the path and confirm it stays within an allow-listed base directory; reject "
        "any input containing path separators or '..'; prefer an opaque id mapped server-side "
        "to a file."
    ),
    "redirect": (
        "Do not redirect to a user-supplied absolute URL. Redirect only to an allow-listed set "
        "of paths, or map an opaque token to a known destination server-side."
    ),
    "cmdi": (
        "Never pass user input to a shell. Call the program directly with an argument vector "
        "(subprocess with a list and shell=False), so there is no shell to inject into. If a "
        "shell is unavoidable, allow-list the input against a strict pattern — escaping is not "
        "enough."
    ),
    "ssti": (
        "Never build template source from user input. Pass user values as template data "
        "(context variables), not into the template string. Use a sandboxed, logic-less engine "
        "for user-authored templates, and keep the template directory out of user control."
    ),
    "crlf": (
        "Reject or strip CR / LF from any user value before it reaches a response header. "
        "Prefer a framework header API that rejects control characters; do not build headers "
        "(Location, Set-Cookie) by string concatenation."
    ),
    "xxe": (
        "Disable DOCTYPE / DTD processing and external-entity resolution in the XML parser "
        "(e.g. defusedxml, or set the parser to forbid DTDs). Do not accept XML where JSON "
        "would do."
    ),
    "ldap": (
        "Escape every user value with the LDAP filter-encoding rules (RFC 4515) before building "
        "a search filter, or use a parameterised directory API. Validate the input against a "
        "strict allow-list and bind with least privilege."
    ),
    "xpath": (
        "Do not build XPath expressions by string concatenation. Use a parameterised /variable "
        "-binding XPath API, or escape and quote user values; validate them against an "
        "allow-list first."
    ),
    "ssi": (
        "Disable SSI / ESI processing on pages that render user input, or HTML-encode the input "
        "so directives cannot form. If SSI is required, keep #exec and #include disabled and "
        "never place untrusted data where the processor parses directives."
    ),
    "xss-stored": (
        "Context-encode all untrusted output (HTML entity, attribute, JavaScript-string, or "
        "URL encoding as appropriate); prefer a templating engine that auto-escapes. Encode on "
        "output, not on input, so stored data is safe wherever it is later rendered. Add a "
        "Content-Security-Policy as defence in depth."
    ),
    "ssrf-metadata": _SSRF_FIX,
    "ssrf-internal": _SSRF_FIX,
}

_REFERENCES: dict[str, tuple[str, ...]] = {
    "xss": (
        f"{_OWASP}/attacks/xss/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ),
    "sqli-error": (
        f"{_OWASP}/attacks/SQL_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    ),
    "sqli-boolean": (
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    ),
    "sqli-time": (
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    ),
    "traversal": (f"{_OWASP}/attacks/Path_Traversal",),
    "redirect": (
        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
    ),
    "xss-stored": (
        f"{_OWASP}/attacks/xss/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ),
    "ssrf-metadata": (
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    ),
    "ssrf-internal": (
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    ),
    "cmdi": (
        f"{_OWASP}/attacks/Command_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
    ),
    "ssti": (
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
        "https://portswigger.net/research/server-side-template-injection",
    ),
    "crlf": (
        f"{_OWASP}/attacks/HTTP_Response_Splitting",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling",
    ),
    "xxe": (
        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
        f"{_OWASP}/attacks/XML_External_Entity_(XXE)_Processing",
    ),
    "ldap": (
        f"{_OWASP}/attacks/LDAP_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
    ),
    "xpath": (
        f"{_OWASP}/attacks/XPATH_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
    ),
    "ssi": (
        f"{_OWASP}/attacks/Server-Side_Includes_(SSI)_Injection",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/08-Testing_for_SSI_Injection",
    ),
}


class _InjectionCheck(Check):
    """
    Shared body: filter ``ctx.observations.injection_hits`` for this check's ``kind``.

    Attributes:
        kind (ClassVar[str]): The ``InjectionHit.kind`` this subclass turns into
            findings; also the key into ``_DESCRIPTION`` / ``_REMEDIATION`` /
            ``_REFERENCES``.
    """

    kind: ClassVar[str]
    category = Category.INJECTION
    mode = ScanMode.ACTIVE

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; reads
                ``observations.injection_hits``.

        Returns:
            list[Finding]: One finding per hit whose kind matches :attr:`kind`.
        """
        return [
            self.finding(
                title=hit.title,
                description=_DESCRIPTION[self.kind],
                remediation=_REMEDIATION[self.kind],
                severity=hit.severity,
                confidence=hit.confidence,
                location=Location(url=hit.url, method=hit.method, param=hit.param),
                evidence=[EvidenceItem.of(label, content) for label, content in hit.evidence],
            )
            for hit in ctx.observations.injection_hits
            if hit.kind == self.kind
        ]


@register
class ReflectedXssCheck(_InjectionCheck):
    """Reflected cross-site scripting from the reflected-XSS detector."""

    id = "injection.xss.reflected"
    name = "Reflected cross-site scripting"
    kind = "xss"
    default_severity = Severity.HIGH
    cwe = (79, 20)
    references = _REFERENCES["xss"]


@register
class SqliErrorBasedCheck(_InjectionCheck):
    """SQL injection confirmed by a DBMS parser error in the response."""

    id = "injection.sqli.error-based"
    name = "SQL injection (error-based)"
    kind = "sqli-error"
    default_severity = Severity.HIGH
    cwe = (89, 209)
    references = _REFERENCES["sqli-error"]


@register
class SqliBooleanBasedCheck(_InjectionCheck):
    """Blind SQL injection confirmed by a reproducible true/false response split."""

    id = "injection.sqli.boolean-based"
    name = "SQL injection (boolean-based blind)"
    kind = "sqli-boolean"
    default_severity = Severity.HIGH
    cwe = (89,)
    references = _REFERENCES["sqli-boolean"]


@register
class SqliTimeBasedCheck(_InjectionCheck):
    """Blind SQL injection confirmed by an attacker-controlled response delay."""

    id = "injection.sqli.time-based"
    name = "SQL injection (time-based blind)"
    kind = "sqli-time"
    default_severity = Severity.HIGH
    cwe = (89,)
    references = _REFERENCES["sqli-time"]


@register
class PathTraversalCheck(_InjectionCheck):
    """Path traversal confirmed by a known system file in the response."""

    id = "injection.traversal.path"
    name = "Path traversal"
    kind = "traversal"
    default_severity = Severity.HIGH
    cwe = (22, 23)
    references = _REFERENCES["traversal"]


@register
class OpenRedirectCheck(_InjectionCheck):
    """Open redirect confirmed by an off-site sentinel host in the redirect target."""

    id = "injection.redirect.open"
    name = "Open redirect"
    kind = "redirect"
    default_severity = Severity.MEDIUM
    cwe = (601,)
    references = _REFERENCES["redirect"]


@register
class StoredXssCheck(_InjectionCheck):
    """Stored / persistent XSS from the two-phase stored-XSS pass (spec 008)."""

    id = "injection.xss.stored"
    name = "Stored cross-site scripting"
    kind = "xss-stored"
    default_severity = Severity.HIGH
    cwe = (79, 20)
    references = _REFERENCES["xss-stored"]


@register
class OsCommandInjectionCheck(_InjectionCheck):
    """OS command injection from the shell-metacharacter echo or time detector (spec 011)."""

    id = "injection.cmdi.os"
    name = "OS command injection"
    kind = "cmdi"
    default_severity = Severity.CRITICAL
    cwe = (78, 77)
    references = _REFERENCES["cmdi"]


@register
class TemplateInjectionCheck(_InjectionCheck):
    """Server-side template injection from the polyglot + arithmetic detector (spec 011)."""

    id = "injection.ssti"
    name = "Server-side template injection"
    kind = "ssti"
    default_severity = Severity.HIGH
    cwe = (1336, 94)
    references = _REFERENCES["ssti"]


@register
class CrlfCheck(_InjectionCheck):
    """CRLF injection / HTTP response splitting: a parameter written into a header (spec 012)."""

    id = "injection.crlf"
    name = "CRLF injection / HTTP response splitting"
    kind = "crlf"
    default_severity = Severity.HIGH
    cwe = (113, 93)
    references = _REFERENCES["crlf"]


@register
class XxeCheck(_InjectionCheck):
    """XML external entity from a POST body re-sent as XML (spec 012, opt-in)."""

    id = "injection.xxe"
    name = "XML external entity (XXE)"
    kind = "xxe"
    default_severity = Severity.HIGH
    cwe = (611, 827)
    references = _REFERENCES["xxe"]


@register
class SsrfMetadataCheck(_InjectionCheck):
    """In-band SSRF that reached a cloud instance-metadata service (spec 009)."""

    id = "injection.ssrf.metadata"
    name = "SSRF — cloud metadata service"
    kind = "ssrf-metadata"
    default_severity = Severity.CRITICAL
    cwe = (918,)
    references = _REFERENCES["ssrf-metadata"]


@register
class SsrfInternalCheck(_InjectionCheck):
    """In-band SSRF that reached a loopback / internal resource or read a local file (spec 009)."""

    id = "injection.ssrf.internal"
    name = "SSRF — internal resource"
    kind = "ssrf-internal"
    default_severity = Severity.HIGH
    cwe = (918,)
    references = _REFERENCES["ssrf-internal"]


@register
class LdapInjectionCheck(_InjectionCheck):
    """LDAP injection — a filter-parser error or a widened result set (spec 014)."""

    id = "injection.ldap"
    name = "LDAP injection"
    kind = "ldap"
    default_severity = Severity.HIGH
    cwe = (90,)
    references = _REFERENCES["ldap"]


@register
class XpathInjectionCheck(_InjectionCheck):
    """XPath / XQuery injection — an expression-parser error or a boolean split (spec 014)."""

    id = "injection.xpath"
    name = "XPath injection"
    kind = "xpath"
    default_severity = Severity.HIGH
    cwe = (643,)
    references = _REFERENCES["xpath"]


@register
class SsiInjectionCheck(_InjectionCheck):
    """Server-Side Includes / ESI injection — a directive the server evaluated (spec 014)."""

    id = "injection.ssi"
    name = "Server-Side Includes (SSI) injection"
    kind = "ssi"
    default_severity = Severity.HIGH
    cwe = (97, 94)
    references = _REFERENCES["ssi"]
