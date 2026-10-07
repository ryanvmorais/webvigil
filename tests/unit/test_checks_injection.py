"""
The injection checks filter hits by kind into findings — spec 006 RF-08..RF-11,
plus stored XSS (spec 008) and SSRF (spec 009).

``_hit`` builds an :class:`~webvigil.checks.injection.models.InjectionHit` as the
scanner passes would leave it on ``Observations.injection_hits``; the checks
issue no HTTP.

Audited under issue #101: six per-spec "metadata and finding shape" tests each rebuilt a hit and
re-asserted what the generic tests below already prove for all 17 checks (it emits only its own
kind, at the hit's location, with the hit's evidence). What was unique in them — the ids, default
severities and CWEs — is now ``test_check_metadata.py``; the references and fix text stay here.
"""

from __future__ import annotations

from tests.support import make_context, make_page
from webvigil.checks.injection.checks import (
    CrlfCheck,
    ExpressionLanguageInjectionCheck,
    LdapInjectionCheck,
    OpenRedirectCheck,
    OsCommandInjectionCheck,
    PathTraversalCheck,
    ReflectedXssCheck,
    SqliBooleanBasedCheck,
    SqliErrorBasedCheck,
    SqliTimeBasedCheck,
    SsiInjectionCheck,
    SsrfInternalCheck,
    SsrfMetadataCheck,
    StoredXssCheck,
    TemplateInjectionCheck,
    XpathInjectionCheck,
    XxeCheck,
)
from webvigil.checks.injection.models import InjectionHit
from webvigil.core.context import Observations
from webvigil.core.findings import Confidence, Severity


def _hit(kind: str) -> InjectionHit:
    """
    Args:
        kind (str): The detector kind the hit carries.

    Returns:
        InjectionHit: A HIGH-severity hit at ``POST https://example.com/s`` on
            parameter ``q``.
    """
    return InjectionHit(
        kind=kind,
        check_id="x",
        method="POST",
        url="https://example.com/s",
        param="q",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title=f"{kind} via the 'q' parameter",
        payload="payload",
        evidence=(
            ("Injection point", "POST https://example.com/s"),
            ("Payload", "payload"),
            ("Rendered on", "https://example.com/guestbook/e/0"),
        ),
    )


_ALL = [
    (ReflectedXssCheck, "xss"),
    (SqliErrorBasedCheck, "sqli-error"),
    (SqliBooleanBasedCheck, "sqli-boolean"),
    (SqliTimeBasedCheck, "sqli-time"),
    (PathTraversalCheck, "traversal"),
    (OpenRedirectCheck, "redirect"),
    (StoredXssCheck, "xss-stored"),
    (SsrfMetadataCheck, "ssrf-metadata"),
    (SsrfInternalCheck, "ssrf-internal"),
    (OsCommandInjectionCheck, "cmdi"),
    (TemplateInjectionCheck, "ssti"),
    (ExpressionLanguageInjectionCheck, "el"),
    (CrlfCheck, "crlf"),
    (XxeCheck, "xxe"),
    (LdapInjectionCheck, "ldap"),
    (XpathInjectionCheck, "xpath"),
    (SsiInjectionCheck, "ssi"),
]


async def test_each_check_emits_only_its_own_kind() -> None:
    """Given one hit of every kind, each check turns exactly its own into a finding."""
    hits = tuple(_hit(kind) for _, kind in _ALL)
    ctx = make_context(make_page(), observations=Observations(injection_hits=hits))
    for check_cls, kind in _ALL:
        findings = await check_cls().run(ctx)
        assert len(findings) == 1, kind
        finding = findings[0]
        assert finding.check_id == check_cls.id
        assert finding.location.param == "q"
        assert finding.location.method == "POST"
        assert finding.location.url == "https://example.com/s"
        assert finding.evidence[1].label == "Payload"
        # the hit severity wins over the check default (SSRF metadata defaults to CRITICAL)
        assert finding.severity is Severity.HIGH, kind
        # extra evidence a detector adds (e.g. the stored-XSS render page) passes through
        assert {e.label: e.content for e in finding.evidence}["Rendered on"].endswith("/e/0")


async def test_no_hits_means_no_findings() -> None:
    """With no hits on the context, every injection check is silent."""
    ctx = make_context(make_page(), observations=Observations())
    for check_cls, _ in _ALL:
        assert await check_cls().run(ctx) == []


async def test_findings_point_a_reader_at_the_right_references_and_fix() -> None:
    """The SSRF and EL findings cite their OWASP / CWE pages; EL names the safe evaluator."""
    assert any("Server_Side_Request_Forgery" in r for r in SsrfMetadataCheck.references)
    el_refs = ExpressionLanguageInjectionCheck.references
    assert any("Expression_Language_Injection" in r for r in el_refs)
    assert any("cwe.mitre.org/data/definitions/917" in r for r in el_refs)
    ctx = make_context(make_page(), observations=Observations(injection_hits=(_hit("el"),)))
    (finding,) = await ExpressionLanguageInjectionCheck().run(ctx)
    assert "expression" in finding.description.lower()
    assert "SimpleEvaluationContext" in finding.remediation
