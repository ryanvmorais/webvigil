"""End-to-end: insecure profile reports the expected findings, hardened reports none — RF-27."""

from __future__ import annotations

import functools

import httpx
import pytest

from tests.fixtures.app import make_app
from webvigil.core import orchestrator as orch_mod
from webvigil.core.config import ScanConfig
from webvigil.core.orchestrator import Orchestrator
from webvigil.core.result import ScanResult
from webvigil.http.client import HttpClient

_TARGET = "http://demo.test/"
# The fixture app is plain HTTP; TLS findings are covered by the socket-based unit tests.
_DISABLED = ["tls.https"]


@pytest.fixture
def scan(monkeypatch: pytest.MonkeyPatch):
    holder: dict[str, object] = {}

    async def _run(
        profile: str,
        *,
        probe: bool = False,
        active: bool = False,
        cookies: list[str] | None = None,
    ) -> ScanResult:
        app = make_app(profile)
        holder["app"] = app
        transport = httpx.ASGITransport(app=app)
        monkeypatch.setattr(
            orch_mod, "HttpClient", functools.partial(HttpClient, transport=transport)
        )
        raw: dict[str, object] = {
            "checks": {"disabled": _DISABLED},
            "disclosure": {"probe": probe},
        }
        if active:
            raw["scan"] = {"mode": "active"}
            raw["active"] = {"authorized_by": "integration test"}
            raw["injection"] = {"time_based_delay_s": 2}
        if cookies is not None:
            raw["auth"] = {"cookies": cookies}
        return await Orchestrator(ScanConfig.model_validate(raw)).run(_TARGET)

    _run.holder = holder  # type: ignore[attr-defined]
    return _run


async def test_insecure_profile_reports_every_expected_check(scan) -> None:
    result = await scan("insecure")
    reported = {finding.check_id for finding in result.findings}
    assert {
        "http.headers.csp",
        "http.headers.frame-options",
        "http.headers.content-type-options",
        "http.headers.referrer-policy",
        "http.headers.permissions-policy",
        "http.headers.cross-origin-isolation",
        "http.headers.revealing",
        "http.cookies.flags",
        "http.cors.misconfiguration",
        "deps.js.vulnerable-library",
    } <= reported
    assert result.errors == ()


async def test_insecure_profile_lists_the_vulnerable_library_in_the_inventory(scan) -> None:
    result = await scan("insecure")
    inventory = {(t.name, t.version, t.vulnerable) for t in result.technologies}
    assert ("jquery", "1.7.1", True) in inventory
    finding = next(f for f in result.findings if f.check_id == "deps.js.vulnerable-library")
    assert "jquery 1.7.1" in finding.title
    assert finding.references


async def test_insecure_profile_passive_disclosure_without_probe(scan) -> None:
    result = await scan("insecure", probe=False)
    reported = {finding.check_id for finding in result.findings}
    assert "disclosure.debug.error-page" in reported
    assert "disclosure.listing.directory-index" in reported
    assert not any(cid.startswith("disclosure.vcs") for cid in reported)
    assert not any(cid.startswith("disclosure.config") for cid in reported)


async def test_insecure_profile_probe_finds_the_exposed_files(scan) -> None:
    result = await scan("insecure", probe=True)
    reported = {finding.check_id for finding in result.findings}
    assert {
        "disclosure.vcs.exposed",
        "disclosure.config.dotenv-exposed",
        "disclosure.config.manifest-exposed",
        "disclosure.debug.error-page",
        "disclosure.listing.directory-index",
    } <= reported
    dotenv = next(f for f in result.findings if f.check_id == "disclosure.config.dotenv-exposed")
    assert "s3cr3t" not in str(dotenv.evidence)
    assert "SECRET_KEY" in str(dotenv.evidence)
    assert result.errors == ()


async def test_insecure_probe_scan_is_deterministic(scan) -> None:
    first = {(f.check_id, f.fingerprint) for f in (await scan("insecure", probe=True)).findings}
    second = {(f.check_id, f.fingerprint) for f in (await scan("insecure", probe=True)).findings}
    assert first == second


async def test_hardened_profile_reports_nothing(scan) -> None:
    for probe in (False, True):
        result = await scan("hardened", probe=probe)
        assert result.findings == ()
        assert result.errors == ()


async def test_crawler_reaches_the_linked_pages(scan) -> None:
    result = await scan("hardened")
    # /, /about, /contact + the four injectable endpoints linked from the index (spec 006)
    # + the GET /search?q= the crawler submits from the search form + /account (→ /login for
    # an anonymous scan) (spec 007 RF-05)
    assert result.metadata.pages_scanned == 9


# --- spec 006: active injection -------------------------------------------------


async def test_insecure_profile_active_finds_every_injection(scan) -> None:
    result = await scan("insecure", active=True)
    reported = {(f.check_id, f.location.param) for f in result.findings}
    assert ("injection.xss.reflected", "q") in reported
    assert ("injection.xss.reflected", "body") in reported
    assert ("injection.sqli.error-based", "id") in reported
    assert ("injection.sqli.boolean-based", "id") in reported
    assert ("injection.sqli.time-based", "id") in reported
    assert ("injection.traversal.path", "file") in reported
    assert ("injection.redirect.open", "next") in reported
    assert result.errors == ()


async def test_passive_scan_issues_no_crafted_request(scan) -> None:
    result = await scan("insecure", active=False)
    assert not any(f.check_id.startswith("injection.") for f in result.findings)
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    assert all("SLEEP" not in entry and "etc/passwd" not in entry for entry in log)


async def test_hardened_profile_active_reports_nothing(scan) -> None:
    result = await scan("hardened", active=True)
    assert not any(f.check_id.startswith("injection.") for f in result.findings)


async def test_the_login_form_is_never_fuzzed(scan) -> None:
    await scan("insecure", active=True)
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    # The crawler may GET /login (it is the redirect target of /account), but the login
    # form is never submitted with a payload.
    assert not any(entry.startswith("POST /login") for entry in log)
    assert not any(entry.startswith("GET /login?") and entry != "GET /login?" for entry in log)


async def test_active_injection_scan_is_deterministic(scan) -> None:
    first = {(f.check_id, f.fingerprint) for f in (await scan("insecure", active=True)).findings}
    second = {(f.check_id, f.fingerprint) for f in (await scan("insecure", active=True)).findings}
    assert first == second


# --- spec 007: authenticated scanning, CSRF, form-driven crawling ---------------


def _urls(result: ScanResult) -> set[str]:
    return {f.location.url for f in result.findings}


async def test_authenticated_scan_reaches_the_account_area(scan) -> None:
    result = await scan("insecure", cookies=["session=abc123"])
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    assert "GET /account?" in log
    assert "GET /account/settings?" in log
    assert result.metadata.authenticated is True


async def test_anonymous_scan_stops_at_the_login_redirect(scan) -> None:
    await scan("insecure")
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    assert not any("/account/settings" in e for e in log)


async def test_crawler_submits_the_get_search_form(scan) -> None:
    await scan("insecure")
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    assert any(e.startswith("GET /search?q=") for e in log)


async def test_crawler_never_submits_post_forms_or_logout(scan) -> None:
    await scan("insecure", cookies=["session=abc123"])  # authenticated, passive
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    assert not any(e.startswith("POST /profile") for e in log)
    assert not any(e.startswith("POST /comment") for e in log)
    assert not any(e.startswith("POST /login") for e in log)
    assert not any("/logout" in e for e in log)


async def test_csrf_check_flags_the_tokenless_profile_form(scan) -> None:
    result = await scan("insecure", cookies=["session=abc123"])
    csrf = [f for f in result.findings if f.check_id == "csrf.form.no-token"]
    assert len(csrf) == 1
    assert csrf[0].location.url.endswith("/profile")
    assert csrf[0].location.method == "POST"


async def test_hardened_authenticated_scan_reports_no_csrf(scan) -> None:
    result = await scan("hardened", cookies=["__Host-session=abc123"])
    assert not any(f.check_id == "csrf.form.no-token" for f in result.findings)


async def test_cookie_value_never_appears_in_any_report(scan) -> None:
    from webvigil.reporting import get_reporter

    result = await scan("insecure", cookies=["session=s3cr3tvalue"])
    for fmt in ("json", "sarif", "html", "md"):
        assert "s3cr3tvalue" not in get_reporter(fmt).render(result)
    assert all("s3cr3tvalue" not in w for w in result.warnings)


async def test_authenticated_scan_is_deterministic(scan) -> None:
    async def _once() -> set[tuple[str, str]]:
        result = await scan("insecure", cookies=["session=abc123"])
        return {(f.check_id, f.fingerprint) for f in result.findings}

    assert await _once() == await _once()
