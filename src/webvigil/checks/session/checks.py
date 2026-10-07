"""
The session-security checks (spec 020, ``Category.SESSION``).

Three thin checks: all the work is done by :class:`~webvigil.checks.session.scanner.SessionScanner`,
which runs once, last, and leaves value-free :class:`~webvigil.checks.session.scanner.SessionHit`
objects on ``ctx.observations.session_hits``. A check turns the hits of its own kind into findings.
The evidence is exactly the hit's facts (names, lengths, rules in words): a cookie value never
reaches a finding (RNF-07).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from webvigil.checks.base import Check
from webvigil.checks.registry import register
from webvigil.core.context import ScanContext
from webvigil.core.findings import Category, EvidenceItem, Finding, Location, ScanMode, Severity

if TYPE_CHECKING:
    from webvigil.checks.session.scanner import SessionHit

_WSTG = (
    "https://owasp.org/www-project-web-security-testing-guide/latest/"
    "4-Web_Application_Security_Testing/06-Session_Management_Testing/"
)
_CWE = "https://cwe.mitre.org/data/definitions/"


class _SessionCheck(Check):
    """
    Base of the three session checks: one finding per hit of ``hit_kind``.

    Attributes:
        hit_kind (str): Which :class:`SessionHit` kind this check reports.
    """

    hit_kind = ""
    category = Category.SESSION

    def _hits(self, ctx: ScanContext) -> list[SessionHit]:
        """
        Args:
            ctx (ScanContext): The scan context.

        Returns:
            list[SessionHit]: The hits of this check's kind, in pass order.
        """
        return [hit for hit in ctx.observations.session_hits if hit.kind == self.hit_kind]

    def _build(self, hit: SessionHit, *, title: str, description: str, remediation: str) -> Finding:
        """
        Args:
            hit (SessionHit): The observation.
            title (str): One-line summary.
            description (str): Full explanation.
            remediation (str): How to fix it.

        Returns:
            Finding: The finding; its dedup key is the kind, never anything derived from a value.
        """
        return self.finding(
            title=title,
            description=description,
            remediation=remediation,
            location=Location(url=hit.url, cookie=hit.name),
            severity=hit.severity,
            confidence=hit.confidence,
            dedup_key=self.hit_kind,
            evidence=[EvidenceItem(label=label, content=content) for label, content in hit.facts],
        )


@register
class WeakSessionIdCheck(_SessionCheck):
    """
    Flags a session id that looks short, low-entropy or predictable.

    Judges the ids the crawl already saw and, with ``--sample-sessions``, a few fresh anonymous
    visits (duplicates, sequences, timestamps, low variance). It sends nothing by itself.
    """

    id = "session.id.weak"
    name = "Weak or predictable session id"
    mode = ScanMode.PASSIVE
    default_severity = Severity.MEDIUM
    hit_kind = "weak"
    cwe = (330, 331, 340)
    references = (
        _WSTG + "01-Testing_for_Session_Management_Schema",
        _CWE + "330.html",
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; reads ``observations.session_hits``.

        Returns:
            list[Finding]: One finding per weak session cookie.
        """
        return [
            self._build(
                hit,
                title=f"Session id '{hit.name}' looks weak ({hit.rule})",
                description=(
                    "A session id must be unguessable: long, random, and drawn from a large "
                    "alphabet. This one looks short, low-entropy or predictable, so an attacker "
                    "may guess or enumerate a valid session. The evidence names the rules that "
                    "fired and never the value."
                ),
                remediation=(
                    "Use the session mechanism of your framework, which draws at least 128 "
                    "random bits from a cryptographic generator, and never build an id from a "
                    "counter, a timestamp, the user name or a hash of them."
                ),
            )
            for hit in self._hits(ctx)
        ]


@register
class SessionFixationCheck(_SessionCheck):
    """
    Flags a session cookie that is the same before and after the login.

    The automated login (spec 019) records the cookies of the login page and of the account;
    a session cookie that did not change, and that the logged-in page needs, lets an attacker who
    planted it before the login share the victim's authenticated session.
    """

    id = "session.fixation"
    name = "Session fixation: the session id survives login"
    mode = ScanMode.ACTIVE
    default_severity = Severity.MEDIUM
    hit_kind = "fixation"
    cwe = (384,)
    references = (
        _WSTG + "03-Testing_for_Session_Fixation",
        _CWE + "384.html",
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; reads ``observations.session_hits``.

        Returns:
            list[Finding]: One finding per fixed session cookie.
        """
        return [
            self._build(
                hit,
                title=f"Session cookie '{hit.name}' is not renewed at login (session fixation)",
                description=(
                    "The server kept the session id it gave an anonymous visitor and made it the "
                    "authenticated session at login. An attacker who plants a known id in a "
                    "victim's browser before the victim logs in then holds the victim's "
                    "authenticated session."
                ),
                remediation=(
                    "Issue a new session id when the user authenticates (and on any privilege "
                    "change) and invalidate the old one; most frameworks do it with one call "
                    "(e.g. session regeneration)."
                ),
            )
            for hit in self._hits(ctx)
        ]


@register
class LogoutNotInvalidatedCheck(_SessionCheck):
    """
    Flags a logout that leaves the old session valid on the server.

    After the logout request, the old session cookies are replayed against a page that needs the
    login; if it still answers as logged in, the server only forgot the cookie in the browser.
    """

    id = "session.logout.not-invalidated"
    name = "Session still valid after logout"
    mode = ScanMode.ACTIVE
    default_severity = Severity.MEDIUM
    hit_kind = "logout"
    cwe = (613,)
    references = (
        _WSTG + "06-Testing_for_Logout_Functionality",
        _CWE + "613.html",
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; reads ``observations.session_hits``.

        Returns:
            list[Finding]: One finding when the old session survived the logout.
        """
        return [
            self._build(
                hit,
                title="The session is still valid after logout",
                description=(
                    "The logout request ended the session in the browser only: replaying the old "
                    "session cookies against a page that needs the login still answered as "
                    "logged in. A stolen or cached session id stays usable until it expires."
                ),
                remediation=(
                    "Destroy the session on the server at logout (delete it from the session "
                    "store, or add a revocation entry for a stateless token) so the old id is "
                    "rejected, not just cleared from the browser."
                ),
            )
            for hit in self._hits(ctx)
        ]
