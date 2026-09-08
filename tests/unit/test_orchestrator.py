"""
Orchestrator: mode gating, check selection, error isolation, dedupe — RF-11, RF-15.

The autouse ``_stub_crawler`` fixture replaces the crawler with one that returns
a single blank page, so the tests exercise the orchestrator's own logic — the
Active gate, fingerprint dedup, per-check error isolation, warning surfacing —
with no HTTP. The check classes (:class:`PassiveOne`, :class:`Boom`, ...) are
tiny local stand-ins that emit canned findings or raise.
"""

from __future__ import annotations

import httpx
import pytest

from webvigil.checks.base import Check
from webvigil.core import orchestrator as orch_mod
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page, ScanContext
from webvigil.core.errors import ActiveModeNotAuthorized
from webvigil.core.findings import Category, Confidence, Location, ScanMode, Severity
from webvigil.core.orchestrator import Orchestrator

_TARGET = "https://example.com/"


def _page() -> Page:
    """
    Returns:
        Page: A single blank HTML page at the target URL.
    """
    return Page(
        requested_url=_TARGET,
        url=_TARGET,
        status_code=200,
        headers=httpx.Headers({"content-type": "text/html"}),
        text="<html></html>",
        elapsed_ms=1.0,
    )


class _StubCrawler:
    """A crawler that discovers exactly one blank page and finds no forms."""

    forms: tuple[object, ...] = ()
    skipped_destructive = 0

    def __init__(self, *_args: object, **_kwargs: object) -> None: ...

    async def discover(self) -> list[Page]:
        return [_page()]


@pytest.fixture(autouse=True)
def _stub_crawler(monkeypatch: pytest.MonkeyPatch) -> None:
    """Swap the orchestrator's ``Crawler`` for :class:`_StubCrawler`."""
    monkeypatch.setattr(orch_mod, "Crawler", _StubCrawler)


class _Base(Check):
    """Shared base for the local test checks: a HEADERS check whose ``_finding`` builds
    a deduplicable finding keyed by an arbitrary string."""

    name = "test check"
    category = Category.HEADERS
    default_severity = Severity.LOW

    def _finding(self, key: str) -> object:
        loc = Location(url=_TARGET, header="X-Test")
        return self.finding(
            title="t",
            description="d",
            remediation="r",
            location=loc,
            confidence=Confidence.HIGH,
            dedup_key=key,
        )


class PassiveOne(_Base):
    id = "test.passive.one"

    async def run(self, ctx: ScanContext) -> list[object]:
        return [self._finding("a")]


class PassiveTwo(_Base):
    id = "test.passive.two"

    async def run(self, ctx: ScanContext) -> list[object]:
        # Same finding emitted twice (e.g. seen on two pages) plus a distinct one.
        return [self._finding("a"), self._finding("a"), self._finding("b")]


class ActiveOne(_Base):
    id = "test.active.one"
    mode = ScanMode.ACTIVE

    async def run(self, ctx: ScanContext) -> list[object]:
        return [self._finding("active")]


class Boom(_Base):
    id = "test.boom"

    async def run(self, ctx: ScanContext) -> list[object]:
        raise RuntimeError("kaboom")


async def test_findings_are_deduped_by_fingerprint() -> None:
    """Findings with the same fingerprint collapse to one; distinct ones are kept."""
    result = await Orchestrator(ScanConfig(), check_types=[PassiveOne, PassiveTwo]).run(_TARGET)
    # PassiveOne("a"), PassiveTwo("a") once (deduped from 2), PassiveTwo("b") -> 3 total.
    assert len(result.findings) == 3
    assert sorted(f.fingerprint for f in result.findings) == sorted(
        {f.fingerprint for f in result.findings}
    )
    assert result.metadata.pages_scanned == 1


async def test_a_raising_check_is_isolated() -> None:
    """A check that raises is recorded as an error; the other checks' findings still land."""
    result = await Orchestrator(ScanConfig(), check_types=[PassiveOne, Boom]).run(_TARGET)
    assert len(result.findings) == 1
    assert [e.check_id for e in result.errors] == ["test.boom"]
    assert "kaboom" in result.errors[0].message


async def test_active_mode_without_authorization_is_rejected() -> None:
    """Active mode with no ``authorized_by`` raises :class:`ActiveModeNotAuthorized`."""
    config = ScanConfig.model_validate({"scan": {"mode": "active"}})
    with pytest.raises(ActiveModeNotAuthorized):
        await Orchestrator(config, check_types=[PassiveOne]).run(_TARGET)


async def test_gated_active_run_records_authorization_and_runs_active_checks() -> None:
    """A properly gated active run records ``authorized_by`` and runs the ACTIVE checks."""
    config = ScanConfig.model_validate(
        {"scan": {"mode": "active"}, "active": {"authorized_by": "Jane / #7"}}
    )
    result = await Orchestrator(config, check_types=[ActiveOne]).run(_TARGET)
    assert result.metadata.authorized_by == "Jane / #7"
    assert len(result.findings) == 1


async def test_authenticated_flag_reflects_configured_cookies() -> None:
    """``metadata.authenticated`` is true only when auth cookies were configured."""
    anon = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert anon.metadata.authenticated is False

    config = ScanConfig.model_validate({"auth": {"cookies": ["session=abc"]}})
    authed = await Orchestrator(config, check_types=[PassiveOne]).run(_TARGET)
    assert authed.metadata.authenticated is True


async def test_forms_reach_a_check_via_ctx(monkeypatch: pytest.MonkeyPatch) -> None:
    """Forms the crawler found are handed to checks through ``ctx.forms``."""
    from webvigil.crawler.forms import Form, FormField

    form = Form(
        method="POST",
        action="https://example.com/x",
        enctype="application/x-www-form-urlencoded",
        fields=(FormField(name="a", type="text", value=""),),
        source_url=_TARGET,
    )
    monkeypatch.setattr(_StubCrawler, "forms", (form,))
    seen: list[object] = []

    class FormReader(_Base):
        id = "test.formreader"

        async def run(self, ctx: ScanContext) -> list[object]:
            seen.extend(ctx.forms)
            return []

    await Orchestrator(ScanConfig(), check_types=[FormReader]).run(_TARGET)
    assert seen == [form]
    monkeypatch.setattr(_StubCrawler, "forms", ())


async def test_destructive_skip_becomes_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """The crawler's destructive-link skip count is surfaced as a scan warning."""
    monkeypatch.setattr(_StubCrawler, "skipped_destructive", 3)
    result = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert any("declined to follow 3 link(s)" in w for w in result.warnings)
    monkeypatch.setattr(_StubCrawler, "skipped_destructive", 0)


async def test_registry_selection_filters_by_mode_and_reports_unknown_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no explicit check types, selection comes from the registry and an unknown
    disabled id is surfaced as a warning."""
    monkeypatch.setattr(orch_mod, "load_plugins", lambda: None)
    monkeypatch.setattr(orch_mod, "iter_checks", lambda *, mode, disabled: [PassiveOne])
    monkeypatch.setattr(orch_mod, "unknown_check_ids", lambda disabled: ["ghost"])

    config = ScanConfig.model_validate({"checks": {"disabled": ["ghost"]}})
    result = await Orchestrator(config).run(_TARGET)

    assert result.warnings == ("unknown disabled check id: ghost",)
    assert len(result.findings) == 1
