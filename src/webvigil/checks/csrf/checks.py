"""
``csrf.form.no-token`` — a state-changing form with no anti-CSRF token (spec 007, RF-08).

Passive. Reads ``ctx.forms`` (the ``<form>``\\s the crawler parsed) and the
``Set-Cookie`` headers of the crawled responses. Confidence is weighted by the
session cookie's ``SameSite``: a token-less ``POST`` form behind a
``SameSite=Lax`` / ``Strict`` session cookie is barely exploitable (``LOW``),
one behind a cookie with no ``SameSite`` is not (``HIGH``).

Known blind spots (documented in ``docs/authenticated-scanning.md``): a token
injected by client-side JavaScript, a token carried in a request header via a
``<meta>`` tag + framework JS (Rails/Angular), and the double-submit-cookie
pattern with no form field — all read here as "no token".
"""

from __future__ import annotations

import re
from http.cookies import SimpleCookie

from webvigil.checks.base import Check
from webvigil.checks.registry import register
from webvigil.core.context import Page, ScanContext
from webvigil.core.findings import Category, Confidence, EvidenceItem, Finding, Location, Severity
from webvigil.crawler.forms import Form, FormField
from webvigil.crawler.safety import is_auth_form, looks_like_search

_TOKEN_NAME_RE = re.compile(
    r"csrf|xsrf|_token|authenticity_token|__requestverificationtoken|csrfmiddlewaretoken|"
    r"nonce|anti[\s_-]?forgery|request[\s_-]?token",
    re.I,
)
_SESSION_NAME_RE = re.compile(r"session|sess(?:id)?|sid|auth|jwt|(?:^|[_-])token", re.I)
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


def _is_token_field(field: FormField) -> bool:
    """
    Args:
        field (FormField): A form control.

    Returns:
        bool: ``True`` when the field name matches a known anti-CSRF token name.
    """
    return bool(_TOKEN_NAME_RE.search(field.name))


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
                if not _SESSION_NAME_RE.search(name):
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
        findings: list[Finding] = []
        for form in ctx.forms:
            if not _is_candidate(form):
                continue
            if any(_is_token_field(field) for field in form.fields):
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


def _is_candidate(form: Form) -> bool:
    """
    Args:
        form (Form): A parsed form.

    Returns:
        bool: ``True`` when the form is a ``POST`` that is neither an auth form
            nor a search form — i.e. a meaningful CSRF target.
    """
    return form.method == "POST" and not is_auth_form(form) and not looks_like_search(form)
