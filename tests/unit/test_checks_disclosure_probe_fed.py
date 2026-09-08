"""
Probe-fed disclosure checks: family filtering, finding shape, evidence — RF-08, RF-10.

``_hit`` builds a :class:`~webvigil.checks.disclosure.probe.ProbeHit` as the
orchestrator's probe pass would leave it; ``_ctx`` puts those on
``Observations.probe_hits``. The checks issue no HTTP.
"""

from __future__ import annotations

from tests.support import make_context, make_page
from webvigil.checks.disclosure.checks import (
    DotenvExposedCheck,
    ManifestExposedCheck,
    VcsExposedCheck,
)
from webvigil.checks.disclosure.probe import ProbeHit
from webvigil.checks.registry import all_checks
from webvigil.core.context import Observations
from webvigil.core.findings import Category, Confidence, Severity

_DISCLOSURE_IDS = {
    "disclosure.debug.error-page",
    "disclosure.listing.directory-index",
    "disclosure.vcs.exposed",
    "disclosure.config.dotenv-exposed",
    "disclosure.config.manifest-exposed",
    "disclosure.backup.file-exposed",
    "disclosure.debug.endpoint-exposed",
    "disclosure.sourcemap.exposed",
    "disclosure.session-id-in-url",  # spec 013
    "disclosure.private-ip",  # spec 013
}


def _hit(family: str, check_id: str, path: str, severity: Severity) -> ProbeHit:
    """
    Args:
        family (str): The probe family.
        check_id (str): The probe-fed check the hit feeds.
        path (str): The reachable path (also forms the URL).
        severity (Severity): Severity carried on the hit.

    Returns:
        ProbeHit: A hit with a fixed redacted body and HIGH confidence.
    """
    return ProbeHit(
        family=family,
        check_id=check_id,
        url=f"https://t.example{path}",
        path=path,
        severity=severity,
        confidence=Confidence.HIGH,
        title="Something exposed",
        description="It leaks.",
        status=200,
        content_type="text/plain",
        redacted_body="KEY=***",
    )


def _ctx(*hits: ProbeHit):
    """
    Args:
        *hits (ProbeHit): The probe hits to seed.

    Returns:
        ScanContext: A context whose ``observations.probe_hits`` holds them.
    """
    return make_context(
        make_page(url="https://t.example/"), observations=Observations(probe_hits=hits)
    )


async def test_each_check_emits_only_its_family() -> None:
    """A check turns only the hits of its own family into findings, carrying the redacted body."""
    ctx = _ctx(
        _hit("vcs", "disclosure.vcs.exposed", "/.git/config", Severity.HIGH),
        _hit("config", "disclosure.config.dotenv-exposed", "/.env", Severity.HIGH),
        _hit("manifest", "disclosure.config.manifest-exposed", "/package.json", Severity.LOW),
    )
    vcs = await VcsExposedCheck().run(ctx)
    assert len(vcs) == 1 and vcs[0].check_id == "disclosure.vcs.exposed"
    assert "/.git/config" in vcs[0].title
    assert vcs[0].severity is Severity.HIGH
    assert vcs[0].evidence[1].content == "KEY=***"

    manifest = await ManifestExposedCheck().run(ctx)
    assert len(manifest) == 1 and manifest[0].severity is Severity.LOW


async def test_severity_comes_from_the_hit_not_the_class_default() -> None:
    """The finding takes the hit's severity even when it differs from the check's default."""
    ctx = _ctx(_hit("config", "disclosure.config.dotenv-exposed", "/web.config", Severity.MEDIUM))
    findings = await DotenvExposedCheck().run(ctx)
    assert findings[0].severity is Severity.MEDIUM  # class default is HIGH


async def test_no_hits_no_findings() -> None:
    """With no probe hits, a probe-fed check produces nothing."""
    assert await VcsExposedCheck().run(_ctx()) == []


async def test_dedup_key_is_the_path() -> None:
    """Two hits at different paths stay two findings (the path is the dedup key)."""
    ctx = _ctx(
        _hit("vcs", "disclosure.vcs.exposed", "/.git/config", Severity.HIGH),
        _hit("vcs", "disclosure.vcs.exposed", "/app/.git/config", Severity.HIGH),
    )
    findings = await VcsExposedCheck().run(ctx)
    assert len({f.fingerprint for f in findings}) == 2


def test_all_disclosure_checks_are_registered() -> None:
    """The registry exposes exactly the expected disclosure check ids, all under DISCLOSURE."""
    ids = {check.id for check in all_checks() if check.id.startswith("disclosure.")}
    assert ids == _DISCLOSURE_IDS
    for check in all_checks():
        if check.id.startswith("disclosure."):
            assert check.category is Category.DISCLOSURE
