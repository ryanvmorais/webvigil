"""
The three session checks — hit to finding — spec 020 RF-10.

All the work is in ``SessionScanner`` (tested in ``test_session_scanner.py``); the checks only
turn the hits of their kind into findings. What is pinned here is the contract users see: the
location carries the URL and the cookie *name*, the dedup key does not depend on the value,
severity and confidence come from the hit, and the evidence is exactly the hit's facts.
"""

from __future__ import annotations

import pytest

from tests.support import make_context, make_page
from webvigil.checks.session.checks import (
    LogoutNotInvalidatedCheck,
    SessionFixationCheck,
    WeakSessionIdCheck,
)
from webvigil.checks.session.scanner import SessionHit
from webvigil.core.context import Observations
from webvigil.core.findings import Category, Confidence, ScanMode, Severity

_HITS = {
    "weak": SessionHit(
        kind="weak",
        name="session",
        url="http://demo.test/",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        rule="sequence",
        facts=(("length", "4"), ("rules", "consecutive visits got consecutive numbers")),
    ),
    "fixation": SessionHit(
        kind="fixation",
        name="sid",
        url="http://demo.test/signin",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        rule="session id kept across login",
        facts=(("cookie", "sid"), ("verified", "yes: the page needs it")),
    ),
    "logout": SessionHit(
        kind="logout",
        name="sid",
        url="http://demo.test/logout",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        rule="old session accepted after logout",
        facts=(("logout", "GET /logout"), ("replayed cookies", "sid")),
    ),
}

_CHECKS = [
    (WeakSessionIdCheck, "weak", "session.id.weak", ScanMode.PASSIVE),
    (SessionFixationCheck, "fixation", "session.fixation", ScanMode.ACTIVE),
    (LogoutNotInvalidatedCheck, "logout", "session.logout.not-invalidated", ScanMode.ACTIVE),
]


@pytest.mark.parametrize(("check_cls", "kind", "check_id", "mode"), _CHECKS)
async def test_a_check_reports_only_the_hits_of_its_own_kind(
    check_cls: type, kind: str, check_id: str, mode: ScanMode
) -> None:
    """Given the hits of all three kinds, each check yields exactly one finding, its own."""
    ctx = make_context(make_page(), observations=Observations(session_hits=tuple(_HITS.values())))

    findings = await check_cls().run(ctx)

    (finding,) = findings
    hit = _HITS[kind]
    assert (finding.check_id, check_cls.mode, check_cls.category) == (
        check_id,
        mode,
        Category.SESSION,
    )
    assert (finding.severity, finding.confidence) == (hit.severity, hit.confidence)
    assert (finding.location.url, finding.location.cookie) == (hit.url, hit.name)
    assert [(e.label, e.content) for e in finding.evidence] == list(hit.facts)
    assert finding.references and finding.cwe


@pytest.mark.parametrize(("check_cls", "kind", "check_id", "mode"), _CHECKS)
async def test_no_hit_means_no_finding(
    check_cls: type, kind: str, check_id: str, mode: ScanMode
) -> None:
    """With nothing observed a check is silent."""
    assert await check_cls().run(make_context(make_page())) == []


async def test_the_fingerprint_depends_on_the_kind_and_the_cookie_name_not_on_anything_else() -> (
    None
):
    """Two runs that observe the same weakness fingerprint the same, whatever the evidence says."""
    base = _HITS["weak"]
    other = SessionHit(
        kind="weak",
        name=base.name,
        url=base.url,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        rule="short",
        facts=(("length", "6"),),
    )
    first = await WeakSessionIdCheck().run(
        make_context(make_page(), observations=Observations(session_hits=(base,)))
    )
    second = await WeakSessionIdCheck().run(
        make_context(make_page(), observations=Observations(session_hits=(other,)))
    )
    renamed = await WeakSessionIdCheck().run(
        make_context(
            make_page(),
            observations=Observations(
                session_hits=(
                    SessionHit("weak", "sid", base.url, base.severity, base.confidence, "x"),
                )
            ),
        )
    )
    assert first[0].fingerprint == second[0].fingerprint
    assert first[0].fingerprint != renamed[0].fingerprint
