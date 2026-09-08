"""
End-to-end: insecure profile reports the expected findings, hardened reports none — RF-27.

Runs the real :class:`Orchestrator` against the in-process fixture app
(``tests/fixtures/app.py``) — ``HttpClient`` is monkeypatched onto an
``ASGITransport`` so a full scan (crawl, checks, active passes) happens with no
sockets. The ``scan`` fixture is the one entry point: it builds the app for a
profile (``"insecure"`` / ``"hardened"``), assembles the config from its
keyword arguments (probe, active, cookies, stored-XSS, OSV), runs the scan, and
exposes the app on ``scan.holder`` so tests can inspect ``app.state.requests``.
``_OSV_JQUERY_RECORD`` + ``_osv_up`` / ``_osv_down`` stub the OSV.dev API.
"""

from __future__ import annotations

import functools
import json
import re

import httpx
import pytest

from tests.fixtures.app import make_app
from webvigil.checks.deps.osv import OsvProvider
from webvigil.core import orchestrator as orch_mod
from webvigil.core.config import ScanConfig
from webvigil.core.orchestrator import Orchestrator
from webvigil.core.result import ScanResult
from webvigil.http.client import HttpClient

_TARGET = "http://demo.test/"
# The fixture app is plain HTTP; TLS findings are covered by the socket-based unit tests.
_DISABLED = ["tls.https"]

# A stand-in OSV.dev record for the fixture's known-vulnerable jQuery 1.7.1 (spec 010).
_OSV_JQUERY_RECORD = {
    "id": "GHSA-jquery-fixture",
    "aliases": ["CVE-2012-6708"],
    "summary": "jQuery selector interpreted as HTML",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "jquery"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.3"}, {"fixed": "1.9.0"}]}
            ],
        }
    ],
    "references": [{"type": "WEB", "url": "https://bugs.jquery.com/ticket/11290"}],
    "database_specific": {"severity": "MODERATE", "cwe_ids": ["CWE-79"]},
}


def _osv_up(request: httpx.Request) -> httpx.Response:
    """An OSV.dev stub that reports jquery vulnerable and serves ``_OSV_JQUERY_RECORD``.

    Args:
        request (httpx.Request): The intercepted OSV.dev request.

    Returns:
        httpx.Response: The batched or per-package response.
    """
    if request.url.path == "/v1/querybatch":
        queries = json.loads(request.content)["queries"]
        results = [
            (
                {"vulns": [{"id": _OSV_JQUERY_RECORD["id"]}]}
                if query["package"]["name"] == "jquery"
                else {}
            )
            for query in queries
        ]
        return httpx.Response(200, json={"results": results})
    if request.url.path == "/v1/query":
        return httpx.Response(200, json={"vulns": [_OSV_JQUERY_RECORD]})
    return httpx.Response(404, json={})


def _osv_down(request: httpx.Request) -> httpx.Response:
    """An OSV.dev stub that always 503s, to model an outage."""
    return httpx.Response(503, json={})


@pytest.fixture
def scan(monkeypatch: pytest.MonkeyPatch):
    """Yield an ``async`` runner that scans the fixture app for a given profile.

    The returned callable takes the profile name plus optional ``probe`` /
    ``active`` / ``cookies`` / ``stored_xss`` / ``osv_online`` / ``osv_up``
    switches, assembles the :class:`ScanConfig`, points the engine's HTTP client
    (and, for OSV, its provider) at in-process transports, runs the scan, and
    returns the :class:`ScanResult`. The built app is stashed on ``scan.holder``
    so a test can read ``app.state.requests``.
    """
    holder: dict[str, object] = {}

    async def _run(
        profile: str,
        *,
        probe: bool = False,
        active: bool = False,
        cookies: list[str] | None = None,
        stored_xss: bool = False,
        osv_online: bool = False,
        osv_up: bool = True,
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
        if active or stored_xss:
            raw["scan"] = {"mode": "active"}
            raw["active"] = {"authorized_by": "integration test"}
            raw["injection"] = {"time_based_delay_s": 2, "stored_xss": stored_xss}
        if cookies is not None:
            raw["auth"] = {"cookies": cookies}
        if osv_online:
            raw["deps"] = {"osv_online": True, "osv_base_url": "http://osv.test"}
            handler = _osv_up if osv_up else _osv_down
            monkeypatch.setattr(
                orch_mod,
                "OsvProvider",
                functools.partial(OsvProvider, transport=httpx.MockTransport(handler)),
            )
        return await Orchestrator(ScanConfig.model_validate(raw)).run(_TARGET)

    _run.holder = holder  # type: ignore[attr-defined]
    return _run


# ---------------------------------------------------------------------------
# Passive headers, cookies, CORS, deps, disclosure, and crawl coverage
# ---------------------------------------------------------------------------


async def test_insecure_profile_reports_every_expected_check(scan) -> None:
    """The insecure profile trips every passive header / cookie / CORS / deps check."""
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
    """The vulnerable jQuery 1.7.1 shows in the inventory and drives a titled finding."""
    result = await scan("insecure")
    inventory = {(t.name, t.version, t.vulnerable) for t in result.technologies}
    assert ("jquery", "1.7.1", True) in inventory
    finding = next(f for f in result.findings if f.check_id == "deps.js.vulnerable-library")
    assert "jquery 1.7.1" in finding.title
    assert finding.references


async def test_osv_online_adds_the_osv_reference_to_the_jquery_finding(scan) -> None:
    """``osv_online`` adds an osv.dev reference to the jQuery finding, with no outage warning."""
    result = await scan("insecure", osv_online=True)
    finding = next(f for f in result.findings if f.check_id == "deps.js.vulnerable-library")
    assert any("osv.dev/vulnerability/" in reference for reference in finding.references)
    assert not any("OSV.dev lookup failed" in warning for warning in result.warnings)


async def test_osv_online_hardened_profile_still_reports_no_deps_findings(scan) -> None:
    """Even with OSV on, the hardened profile has no vulnerable library to report."""
    result = await scan("hardened", osv_online=True)
    assert not any(f.check_id.startswith("deps.") for f in result.findings)


async def test_osv_outage_warns_and_keeps_the_offline_finding(scan) -> None:
    """An OSV outage is a warning; the offline finding stays but gains no osv.dev reference."""
    result = await scan("insecure", osv_online=True, osv_up=False)
    assert any("OSV.dev lookup failed" in warning for warning in result.warnings)
    finding = next(f for f in result.findings if f.check_id == "deps.js.vulnerable-library")
    assert not any("osv.dev/vulnerability/" in reference for reference in finding.references)


async def test_osv_online_scan_is_deterministic(scan) -> None:
    """Two OSV-online scans of the same profile produce the same findings in the same order."""
    first = await scan("insecure", osv_online=True)
    second = await scan("insecure", osv_online=True)
    assert [f.fingerprint for f in first.findings] == [f.fingerprint for f in second.findings]


async def test_osv_not_queried_without_the_opt_in(scan) -> None:
    """Without ``osv_online`` the jQuery finding carries no osv.dev reference."""
    result = await scan("insecure")
    finding = next(f for f in result.findings if f.check_id == "deps.js.vulnerable-library")
    assert not any("osv.dev/vulnerability/" in reference for reference in finding.references)


async def test_insecure_profile_passive_disclosure_without_probe(scan) -> None:
    """Without ``--probe`` only the passive disclosure checks fire (error page, dir listing)."""
    result = await scan("insecure", probe=False)
    reported = {finding.check_id for finding in result.findings}
    assert "disclosure.debug.error-page" in reported
    assert "disclosure.listing.directory-index" in reported
    assert not any(cid.startswith("disclosure.vcs") for cid in reported)
    assert not any(cid.startswith("disclosure.config") for cid in reported)


async def test_insecure_profile_probe_finds_the_exposed_files(scan) -> None:
    """``--probe`` finds the exposed .git / .env / manifest and redacts the .env secret."""
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
    """Two probe scans of the insecure profile yield the same set of findings."""
    first = {(f.check_id, f.fingerprint) for f in (await scan("insecure", probe=True)).findings}
    second = {(f.check_id, f.fingerprint) for f in (await scan("insecure", probe=True)).findings}
    assert first == second


async def test_hardened_profile_reports_nothing(scan) -> None:
    """The hardened profile reports no findings and no errors, with or without ``--probe``."""
    for probe in (False, True):
        result = await scan("hardened", probe=probe)
        assert result.findings == ()
        assert result.errors == ()


async def test_crawler_reaches_the_linked_pages(scan) -> None:
    """The crawler reaches all 12 linked pages of the fixture app (index, forms, endpoints)."""
    result = await scan("hardened")
    # /, /about, /contact + the injectable endpoints linked from the index: /search, /item,
    # /download, /go (spec 006) and /fetch, /webhook (spec 009) + the GET /search?q= the
    # crawler submits from the search form + /account (→ /login for an anonymous scan)
    # (spec 007 RF-05) + /guestbook (spec 008 RF-13)
    assert result.metadata.pages_scanned == 12


# ---------------------------------------------------------------------------
# Active injection (spec 006 / 009)
# ---------------------------------------------------------------------------


async def test_insecure_profile_active_finds_every_injection(scan) -> None:
    """An active scan finds every seeded injection kind (XSS, SQLi, traversal, open redirect)."""
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


async def test_ssrf_metadata_found_on_the_insecure_fetch_endpoint(scan) -> None:
    """The ``/fetch`` endpoint yields a CRITICAL cloud-metadata SSRF finding on ``url``."""
    result = await scan("insecure", active=True)
    meta = [f for f in result.findings if f.check_id == "injection.ssrf.metadata"]
    assert meta, "expected a cloud-metadata SSRF finding"
    finding = meta[0]
    assert finding.location.param == "url"
    assert finding.severity.name == "CRITICAL"
    assert "AccessKeyId" in " ".join(e.content for e in finding.evidence)


async def test_ssrf_internal_found_on_the_insecure_webhook_endpoint(scan) -> None:
    """The ``/webhook`` endpoint yields an internal-resource SSRF finding on ``callback``."""
    result = await scan("insecure", active=True)
    internal = [f for f in result.findings if f.check_id == "injection.ssrf.internal"]
    assert internal, "expected an internal-resource SSRF finding"
    assert any(f.location.param == "callback" for f in internal)


async def test_hardened_fetch_endpoints_report_no_ssrf(scan) -> None:
    """The hardened profile's fetch endpoints validate the URL, so no SSRF is found."""
    result = await scan("hardened", active=True)
    assert not any(f.check_id.startswith("injection.ssrf.") for f in result.findings)


async def test_ssrf_scan_is_deterministic(scan) -> None:
    """Two active scans produce the same set of SSRF finding fingerprints."""
    a = await scan("insecure", active=True)
    b = await scan("insecure", active=True)
    ssrf_a = sorted(f.fingerprint for f in a.findings if f.check_id.startswith("injection.ssrf."))
    ssrf_b = sorted(f.fingerprint for f in b.findings if f.check_id.startswith("injection.ssrf."))
    assert ssrf_a == ssrf_b and ssrf_a


async def test_passive_scan_issues_no_crafted_request(scan) -> None:
    """A passive scan sends no payload — no ``SLEEP``, no ``etc/passwd`` in the request log."""
    result = await scan("insecure", active=False)
    assert not any(f.check_id.startswith("injection.") for f in result.findings)
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    assert all("SLEEP" not in entry and "etc/passwd" not in entry for entry in log)


async def test_hardened_profile_active_reports_nothing(scan) -> None:
    """The hardened profile reports no injection findings under an active scan."""
    result = await scan("hardened", active=True)
    assert not any(f.check_id.startswith("injection.") for f in result.findings)


async def test_the_login_form_is_never_fuzzed(scan) -> None:
    """The login form is never submitted with a payload, even during an active scan."""
    await scan("insecure", active=True)
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    # The crawler may GET /login (it is the redirect target of /account), but the login
    # form is never submitted with a payload.
    assert not any(entry.startswith("POST /login") for entry in log)
    assert not any(entry.startswith("GET /login?") and entry != "GET /login?" for entry in log)


async def test_active_injection_scan_is_deterministic(scan) -> None:
    """Two active scans of the insecure profile produce the same finding set."""
    first = {(f.check_id, f.fingerprint) for f in (await scan("insecure", active=True)).findings}
    second = {(f.check_id, f.fingerprint) for f in (await scan("insecure", active=True)).findings}
    assert first == second


# ---------------------------------------------------------------------------
# Authenticated scanning, CSRF, form-driven crawling (spec 007)
# ---------------------------------------------------------------------------


def _urls(result: ScanResult) -> set[str]:
    """
    Args:
        result (ScanResult): A finished scan result.

    Returns:
        set[str]: The distinct location URLs across its findings.
    """
    return {f.location.url for f in result.findings}


async def test_authenticated_scan_reaches_the_account_area(scan) -> None:
    """With a session cookie the crawl reaches the behind-login account pages."""
    result = await scan("insecure", cookies=["session=abc123"])
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    assert "GET /account?" in log
    assert "GET /account/settings?" in log
    assert result.metadata.authenticated is True


async def test_anonymous_scan_stops_at_the_login_redirect(scan) -> None:
    """An anonymous scan cannot get past the login redirect into the account area."""
    await scan("insecure")
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    assert not any("/account/settings" in e for e in log)


async def test_crawler_submits_the_get_search_form(scan) -> None:
    """The crawler submits the safe GET search form."""
    await scan("insecure")
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    assert any(e.startswith("GET /search?q=") for e in log)


async def test_crawler_never_submits_post_forms_or_logout(scan) -> None:
    """The crawler never POSTs a form or follows a logout link, even authenticated."""
    await scan("insecure", cookies=["session=abc123"])  # authenticated, passive
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    assert not any(e.startswith("POST /profile") for e in log)
    assert not any(e.startswith("POST /comment") for e in log)
    assert not any(e.startswith("POST /login") for e in log)
    assert not any("/logout" in e for e in log)


async def test_csrf_check_flags_the_tokenless_profile_form(scan) -> None:
    """The tokenless POST ``/profile`` form is flagged once by the CSRF check."""
    result = await scan("insecure", cookies=["session=abc123"])
    csrf = [f for f in result.findings if f.check_id == "csrf.form.no-token"]
    assert len(csrf) == 1
    assert csrf[0].location.url.endswith("/profile")
    assert csrf[0].location.method == "POST"


async def test_hardened_authenticated_scan_reports_no_csrf(scan) -> None:
    """The hardened profile's forms carry a token, so the CSRF check stays quiet."""
    result = await scan("hardened", cookies=["__Host-session=abc123"])
    assert not any(f.check_id == "csrf.form.no-token" for f in result.findings)


async def test_cookie_value_never_appears_in_any_report(scan) -> None:
    """The supplied session cookie value never leaks into any report format or a warning."""
    from webvigil.reporting import get_reporter

    result = await scan("insecure", cookies=["session=s3cr3tvalue"])
    for fmt in ("json", "sarif", "html", "md"):
        assert "s3cr3tvalue" not in get_reporter(fmt).render(result)
    assert all("s3cr3tvalue" not in w for w in result.warnings)


async def test_authenticated_scan_is_deterministic(scan) -> None:
    """Two authenticated scans of the insecure profile produce the same finding set."""

    async def _once() -> set[tuple[str, str]]:
        result = await scan("insecure", cookies=["session=abc123"])
        return {(f.check_id, f.fingerprint) for f in result.findings}

    assert await _once() == await _once()


# ---------------------------------------------------------------------------
# Stored / persistent XSS (spec 008)
# ---------------------------------------------------------------------------


def _stored(result: ScanResult):
    """
    Args:
        result (ScanResult): A finished scan result.

    Returns:
        list[Finding]: Its ``injection.xss.stored`` findings.
    """
    return [f for f in result.findings if f.check_id == "injection.xss.stored"]


async def test_stored_xss_found_on_the_insecure_guestbook(scan) -> None:
    """The stored-XSS pass finds the guestbook sink: POST ``body``, rendered on a per-entry page."""
    result = await scan("insecure", stored_xss=True)
    stored = _stored(result)
    gb = next((f for f in stored if f.location.url.endswith("/guestbook")), None)
    assert gb is not None
    assert (gb.location.method, gb.location.param) == ("POST", "body")
    rendered_on = {e.label: e.content for e in gb.evidence}["Rendered on"]
    assert "/guestbook/e/" in rendered_on
    assert result.errors == ()


async def test_stored_xss_render_location_is_the_per_entry_page(scan) -> None:
    """The marker's render page was never seen by the first crawl; the re-crawl reached it."""
    result = await scan("insecure", stored_xss=True)
    gb = next(f for f in _stored(result) if f.location.url.endswith("/guestbook"))
    # /guestbook only lists links; the raw marker renders on /guestbook/e/<id>, which the
    # first crawl never saw — proving the one-hop re-crawl reached it.
    rendered_on = {e.label: e.content for e in gb.evidence}["Rendered on"]
    assert re.search(r"/guestbook/e/\d+", rendered_on)


async def test_stored_xss_not_run_without_the_opt_in(scan) -> None:
    """An active scan without ``stored_xss`` never runs the Phase B re-crawl of the entry pages."""
    result = await scan("insecure", active=True)
    assert _stored(result) == []
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    # the per-entry pages are only fetched by the Phase B re-crawl, which never ran
    assert not any(e.startswith("GET /guestbook/e/") for e in log)


async def test_stored_xss_passive_scan_does_nothing(scan) -> None:
    """A passive scan submits no marker to the guestbook."""
    result = await scan("insecure")
    assert _stored(result) == []
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    assert not any(e.startswith("POST /guestbook") for e in log)


async def test_hardened_profile_reports_no_stored_xss(scan) -> None:
    """The hardened guestbook escapes the marker, so no stored-XSS finding results."""
    result = await scan("hardened", stored_xss=True)
    assert not any(f.check_id.startswith("injection.") for f in result.findings)


async def test_authenticated_stored_xss_reaches_the_account_area_and_keeps_the_cookie_private(
    scan,
) -> None:
    """Authenticated stored-XSS reaches the behind-login sink and keeps the cookie private."""
    result = await scan("insecure", cookies=["session=s3cr3t008"], stored_xss=True)
    from webvigil.reporting import get_reporter

    params = {(f.location.method, f.location.param) for f in _stored(result)}
    assert ("POST", "nickname") in params  # the behind-login /profile → /account/settings sink
    for fmt in ("json", "sarif", "html", "md"):
        assert "s3cr3t008" not in get_reporter(fmt).render(result)


async def test_stored_xss_scan_is_deterministic(scan) -> None:
    """Two stored-XSS scans of the insecure profile produce the same finding set."""

    async def _once() -> set[tuple[str, str]]:
        result = await scan("insecure", stored_xss=True)
        return {(f.check_id, f.fingerprint) for f in result.findings}

    assert await _once() == await _once()
