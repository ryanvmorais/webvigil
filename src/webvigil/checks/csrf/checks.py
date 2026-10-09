"""
CSRF checks: ``csrf.form.no-token`` (spec 007, RF-08), ``csrf.form.token-not-enforced`` (017) and
``csrf.form.state-change-over-get`` (issue #144).

``csrf.form.no-token`` — a state-changing form with no anti-CSRF token. Passive.
Reads ``ctx.forms`` (the ``<form>``\\s the crawler parsed) and the
``Set-Cookie`` headers of the crawled responses. Confidence is weighted by the
session cookie's ``SameSite``: a token-less ``POST`` form behind a
``SameSite=Lax`` / ``Strict`` session cookie is barely exploitable (``LOW``),
one behind a cookie with no ``SameSite`` is not (``HIGH``).

Known blind spots (documented in ``docs/authenticated-scanning.md``): a token
injected by client-side JavaScript, a token carried in a request header via a
``<meta>`` tag + framework JS (Rails/Angular), and the double-submit-cookie
pattern with no form field — all read here as "no token".

``csrf.form.token-not-enforced`` is the active counterpart. It issues no request itself:
:class:`~webvigil.checks.csrf.scanner.CsrfScanner` (an orchestrator pass, opt-in
``--confirm-csrf``) replayed each form without a valid token, and this check turns the forms
the server accepted into findings. A form it confirms replaces the passive finding for the
same action, so one proof is never reported twice.

``csrf.form.state-change-over-get`` — a ``GET`` form that changes state (a password change, a
destructive verb in the action). Passive. ``csrf.form.no-token`` reads ``POST`` forms only, and a
cross-site link or image is enough to submit a ``GET`` one, so ``SameSite=Lax`` does not help.
"""

from __future__ import annotations

from http.cookies import SimpleCookie

from webvigil.checks.base import Check
from webvigil.checks.csrf.tokens import is_candidate, is_token_field
from webvigil.checks.registry import register
from webvigil.checks.session.cookies import SESSION_NAME_RE
from webvigil.core.context import Page, ScanContext
from webvigil.core.findings import (
    Category,
    Confidence,
    EvidenceItem,
    Finding,
    Location,
    ScanMode,
    Severity,
)
from webvigil.crawler.safety import state_change_signal

_PROTECTION = {"strict": 2, "lax": 1, "none": 0}

OWASP_CSRF = "https://owasp.org/www-community/attacks/csrf"
_WSTG = "https://owasp.org/www-project-web-security-testing-guide/"

_DESCRIPTION = (
    "This form performs a state-changing POST but carries no anti-CSRF token in a hidden "
    "field. If the session is authenticated by a cookie the browser sends on cross-site "
    "requests, another origin can submit this form on the victim's behalf. WebVigil "
    "inspects the served HTML only, so a token injected by JavaScript, carried in a request "
    "header, or implemented as a double-submit cookie is not visible here."
)
_REMEDIATION = (
    "Add a per-session (or per-request) anti-CSRF token as a hidden field and reject any "
    "POST whose token is missing or wrong. Set the session cookie to SameSite=Lax or "
    "Strict as defence in depth. If the token is added by client-side code or sent as a "
    "header, confirm the server actually enforces it."
)

_CONFIDENCE = {
    None: Confidence.MEDIUM,
    "none": Confidence.HIGH,
    "lax": Confidence.LOW,
    "strict": Confidence.LOW,
}
_SAMESITE_NOTE = {
    None: "no session cookie observed during the crawl",
    "none": "session cookie has no SameSite attribute — sent on cross-site requests",
    "lax": "session cookie is SameSite=Lax — mitigates, but not for top-level POST navigations",
    "strict": "session cookie is SameSite=Strict — strongly mitigates cross-site submission",
}


def _weaker(current: str | None, candidate: str) -> str:
    """
    Args:
        current (str | None): The weakest ``SameSite`` seen so far, or ``None``.
        candidate (str): A newly observed ``SameSite`` value; anything
            unrecognised counts as ``"none"``.

    Returns:
        str: Whichever of the two offers less CSRF protection.
    """
    cand = candidate if candidate in _PROTECTION else "none"
    if current is None or _PROTECTION[cand] < _PROTECTION[current]:
        return cand
    return current


def _session_samesite(pages: tuple[Page, ...]) -> str | None:
    """
    Args:
        pages (tuple[Page, ...]): The crawled pages, for their ``Set-Cookie``
            headers.

    Returns:
        str | None: The weakest ``SameSite`` seen on a session-looking cookie
            across the crawl, or ``None`` when no session cookie was observed.
    """
    seen: str | None = None
    for page in pages:
        for raw in page.headers.get_list("set-cookie"):
            jar: SimpleCookie = SimpleCookie()
            try:
                jar.load(raw)
            except Exception:  # a malformed Set-Cookie must not break the check
                continue
            for name, morsel in jar.items():
                if not SESSION_NAME_RE.search(name):
                    continue
                samesite = (morsel["samesite"] or "none").strip().lower() or "none"
                seen = _weaker(seen, samesite)
    return seen


@register
class NoCsrfTokenCheck(Check):
    """
    Flags every state-changing ``POST`` form that carries no anti-CSRF token field.

    Auth and search forms are excluded. Confidence tracks the session cookie's
    ``SameSite``: HIGH with no ``SameSite``, LOW with ``Lax`` / ``Strict``,
    MEDIUM when no session cookie was seen.
    """

    id = "csrf.form.no-token"
    name = "Form without an anti-CSRF token"
    category = Category.CSRF
    default_severity = Severity.MEDIUM
    cwe = (352,)
    references = (OWASP_CSRF, _WSTG)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; reads ``ctx.forms`` and the
                pages' ``Set-Cookie`` headers.

        Returns:
            list[Finding]: One finding per token-less state-changing form.
        """
        samesite = _session_samesite(ctx.pages)
        confidence = _CONFIDENCE[samesite]
        confirmed = {hit.url for hit in ctx.observations.csrf_hits}  # spec 017: active wins
        findings: list[Finding] = []
        for form in ctx.forms:
            if not is_candidate(form) or form.action in confirmed:
                continue
            if any(is_token_field(field) for field in form.fields):
                continue
            field_names = ", ".join(field.name for field in form.fields) or "(none)"
            evidence_form = f"POST {form.action}  (found on {form.source_url})"
            findings.append(
                self.finding(
                    title=f"POST form to {form.action} has no anti-CSRF token",
                    description=_DESCRIPTION,
                    remediation=_REMEDIATION,
                    confidence=confidence,
                    location=Location(url=form.action, method="POST"),
                    dedup_key="no-token",
                    evidence=[
                        EvidenceItem.of("form", evidence_form),
                        EvidenceItem.of("fields", field_names),
                        EvidenceItem.of("session cookie", _SAMESITE_NOTE[samesite]),
                    ],
                )
            )
        return findings


_GET_DESCRIPTION = (
    "This form changes state over GET: {why}. A GET request needs no form, so any page the "
    "victim opens can submit it with a link, an image or a redirect, and SameSite=Lax does not "
    "stop it because the browser still sends a Lax cookie on a top-level navigation. The "
    "values also end up in the URL, the browser history, the server logs and the Referer "
    "header. WebVigil reads the form's shape and does not submit it, so it cannot say the "
    "server acts on the request."
)
_GET_REMEDIATION = (
    "Make the action a POST (or PUT / DELETE) and protect it with an anti-CSRF token validated "
    "on the server, then ask for the current password before a password change. A state change "
    "must never be reachable by a GET."
)
_GET_WHY = {
    "password change": "it has password fields for a new password and its confirmation",
    "destructive verb": "its action or fields name a destructive operation",
}
# SameSite=Lax is no defence against a GET (the cookie rides a top-level navigation); only
# Strict is. The form's shape is a heuristic, so no cookie evidence is never better than MEDIUM.
_GET_CONFIDENCE = {
    None: Confidence.LOW,
    "none": Confidence.MEDIUM,
    "lax": Confidence.MEDIUM,
    "strict": Confidence.LOW,
}
_GET_SAMESITE_NOTE = {
    None: "no session cookie observed during the crawl",
    "none": "session cookie has no SameSite attribute — sent on cross-site requests",
    "lax": "session cookie is SameSite=Lax — still sent when a cross-site link is followed",
    "strict": "session cookie is SameSite=Strict — not sent on a cross-site request",
}


@register
class GetStateChangeCheck(Check):
    """
    Flags a ``GET`` form that changes state and carries no anti-CSRF token.

    A form qualifies by its shape, not by a guess about a free-text field: password fields for
    a new password and its confirmation, or a destructive verb in the action (see
    :func:`~webvigil.crawler.safety.state_change_signal`). Search forms and login forms never
    qualify. Confidence follows the session cookie's ``SameSite`` (``Lax`` does not mitigate a
    ``GET``) and is ``MEDIUM`` at most, because the form is recognised by its shape.
    """

    id = "csrf.form.state-change-over-get"
    name = "State-changing form submitted with GET"
    category = Category.CSRF
    default_severity = Severity.MEDIUM
    cwe = (352, 650)
    references = (OWASP_CSRF, _WSTG)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; reads ``ctx.forms`` and the pages'
                ``Set-Cookie`` headers.

        Returns:
            list[Finding]: One finding per ``GET`` form that looks state-changing.
        """
        samesite = _session_samesite(ctx.pages)
        findings: list[Finding] = []
        for form in ctx.forms:
            signal = state_change_signal(form)
            if signal is None or any(is_token_field(field) for field in form.fields):
                continue
            field_names = ", ".join(field.name for field in form.fields) or "(none)"
            findings.append(
                self.finding(
                    title=f"GET form to {form.action} changes state",
                    description=_GET_DESCRIPTION.format(why=_GET_WHY[signal]),
                    remediation=_GET_REMEDIATION,
                    confidence=_GET_CONFIDENCE[samesite],
                    location=Location(url=form.action, method="GET"),
                    dedup_key="state-change-over-get",
                    evidence=[
                        EvidenceItem.of("form", f"GET {form.action}  (found on {form.source_url})"),
                        EvidenceItem.of("fields", field_names),
                        EvidenceItem.of("why", signal),
                        EvidenceItem.of("session cookie", _GET_SAMESITE_NOTE[samesite]),
                    ],
                )
            )
        return findings


_ACTIVE_DESCRIPTION = (
    "WebVigil submitted this state-changing form the way a legitimate user would, then again "
    "the way a cross-site page would: a foreign Origin and Referer, and the anti-CSRF token "
    "removed or altered (or, when the form carries none, as served). The server answered the "
    "second request like the first, so it does not enforce a token on this endpoint. If the "
    "session is carried by a cookie the browser sends on cross-site requests, another origin "
    "can submit this form on the victim's behalf. WebVigil is not a browser and cannot show "
    "that the cookie would be sent: the confidence reflects the cookie's SameSite attribute."
)
_ACTIVE_REMEDIATION = (
    "Validate a per-session (or per-request) anti-CSRF token on every state-changing request "
    "and reject any whose token is missing or wrong, then verify the Origin / Referer header "
    "and set the session cookie to SameSite=Lax or Strict as defence in depth. Retest by "
    "replaying the form without the token: it must be refused."
)


@register
class TokenNotEnforcedCheck(Check):
    """
    A state-changing form the server accepted without a valid anti-CSRF token.

    Turns the hits of the active confirmation pass into findings; issues no
    request. Confidence follows the session cookie's ``SameSite`` as in the passive
    check, and is capped at ``MEDIUM`` unless a session cookie is configured: a
    replay with no ambient credential proves the form takes an anonymous post, not
    that a logged-in victim can be forced to make one.
    """

    id = "csrf.form.token-not-enforced"
    name = "Form accepted without a valid anti-CSRF token"
    category = Category.CSRF
    mode = ScanMode.ACTIVE
    default_severity = Severity.MEDIUM
    cwe = (352,)
    references = (OWASP_CSRF, _WSTG)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; reads ``observations.csrf_hits``,
                the pages' ``Set-Cookie`` headers and ``config.auth.cookies``.

        Returns:
            list[Finding]: One finding per confirmed form.
        """
        samesite = _session_samesite(ctx.pages)
        confidence = _CONFIDENCE[samesite]
        has_cookies = ctx.config.auth.has_session
        if not has_cookies:
            confidence = min(confidence, Confidence.MEDIUM)
        credentials = "session cookies configured" if has_cookies else "none - an anonymous replay"
        return [
            self.finding(
                title=(
                    f"POST form to {hit.url} accepted a cross-site request without a valid "
                    "anti-CSRF token"
                ),
                description=_ACTIVE_DESCRIPTION,
                remediation=_ACTIVE_REMEDIATION,
                confidence=confidence,
                location=Location(url=hit.url, method="POST"),
                dedup_key="not-enforced",
                evidence=[
                    EvidenceItem.of("form", f"POST {hit.url}  (found on {hit.source_url})"),
                    EvidenceItem.of("replay", hit.replay),
                    EvidenceItem.of("control", hit.control),
                    EvidenceItem.of("replay response", hit.attack),
                    EvidenceItem.of("credentials", credentials),
                    EvidenceItem.of("session cookie", _SAMESITE_NOTE[samesite]),
                ],
            )
            for hit in ctx.observations.csrf_hits
        ]
