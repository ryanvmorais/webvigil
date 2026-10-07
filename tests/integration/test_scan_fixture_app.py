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
from pathlib import Path

import httpx
import pytest

from tests.fixtures.app import make_app
from tests.support import make_finding, make_result
from webvigil.checks.deps.osv import OsvProvider
from webvigil.core import orchestrator as orch_mod
from webvigil.core.config import ScanConfig
from webvigil.core.findings import Finding, Severity
from webvigil.core.orchestrator import Orchestrator
from webvigil.core.result import ScanResult
from webvigil.http.client import HttpClient
from webvigil.reporting import get_reporter

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


def _assert_same_findings(first: ScanResult, second: ScanResult) -> None:
    """Assert two scans reported the same findings, and name the ones that differ if not.

    Comparing bare fingerprints leaves a failure unreadable: the one run that flaked
    (issue #58) only showed that scan A had an extra hash. This lists the check, the
    location and the title of whatever is in only one of the two scans, so a flaky run
    explains itself.

    Args:
        first (ScanResult): The first scan.
        second (ScanResult): The second scan.
    """
    a = {f.fingerprint: f for f in first.findings}
    b = {f.fingerprint: f for f in second.findings}

    def describe(findings: dict[str, Finding], fingerprints: set[str]) -> list[str]:
        return [
            f"{f.check_id}  {f.location.method} {f.location.url}"
            f"  param={f.location.param}  {f.title}"
            for f in (findings[key] for key in sorted(fingerprints))
        ]

    only_first = describe(a, a.keys() - b.keys())
    only_second = describe(b, b.keys() - a.keys())
    assert not only_first and not only_second, (
        "the two scans differ\n  only in the first:  "
        + ("\n                      ".join(only_first) or "-")
        + "\n  only in the second: "
        + ("\n                      ".join(only_second) or "-")
    )


@pytest.fixture
def scan(monkeypatch: pytest.MonkeyPatch):
    """Yield an ``async`` runner that scans the fixture app for a given profile.

    The returned callable takes the profile name plus optional ``probe`` /
    ``active`` / ``cookies`` / ``stored_xss`` / ``xxe`` / ``file_upload`` /
    ``confirm_csrf`` / ``post_forms`` / ``openapi`` / ``osv_online`` / ``osv_up`` /
    ``time_based`` switches, assembles the :class:`ScanConfig`, points the engine's HTTP client
    (and, for OSV, its provider) at in-process transports, runs the scan, and
    returns the :class:`ScanResult`. The built app is stashed on ``scan.holder``
    so a test can read ``app.state.requests``. ``time_based=False`` turns off the
    time-delay SQLi and command-injection detectors of an active scan: they decide on
    wall-clock response times, which a loaded runner can distort.
    """
    holder: dict[str, object] = {}

    async def _run(
        profile: str,
        *,
        probe: bool = False,
        active: bool = False,
        cookies: list[str] | None = None,
        headers: list[str] | None = None,
        stored_xss: bool = False,
        xxe: bool = False,
        file_upload: bool = False,
        confirm_csrf: bool = False,
        post_forms: bool = False,
        openapi: str | None = None,
        osv_online: bool = False,
        osv_up: bool = True,
        time_based: bool = True,
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
            # A wider page budget for the stored-XSS re-crawl: an active scan of the insecure
            # profile now fuzzes ~13 injection points (spec 011 added /ping, /greet; spec 014
            # added /dir?user, /xdoc?node, /page?tpl and the ldap/xpath/ssi detectors), and
            # every POST-form
            # payload leaves a guestbook entry the Phase-B re-crawl walks past to reach the
            # marker's own entry. The request budget is raised past the model default so the
            # slow sqli-time / stored-XSS phases still run on this unusually dense fixture.
            raw["scan"] = {"mode": "active", "max_pages": 90}
            raw["active"] = {"authorized_by": "integration test"}
            raw["injection"] = {
                "time_based_sqli": time_based,
                "time_based_cmdi": time_based,
                "time_based_delay_s": 2,
                "request_budget": 1200,
                "stored_xss": stored_xss,
                "xxe": xxe,
                "file_upload": file_upload,
                "csrf_confirm": confirm_csrf,
                # keep the spec-012 envelope pass small for the fixture; the sample takes the
                # entry, then every form action, then the other pages, so the form actions of
                # spec 017 (/panel, four) and spec 018 (/support, three) pushed /reset and
                # /resource out of the earlier samples of 20 and then 24
                "envelope_url_sample": 30,
                "envelope_budget": 180,
            }
        if post_forms:
            raw.setdefault("scan", {})
            raw["scan"]["submit_post_forms"] = True  # type: ignore[index]
        if openapi is not None:
            raw.setdefault("scan", {})
            raw["scan"]["openapi"] = openapi  # type: ignore[index]
        if cookies is not None or headers is not None:
            raw["auth"] = {"cookies": cookies or [], "headers": headers or []}
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
    """The crawler reaches all 25 linked pages of the fixture app (index, forms, endpoints)."""
    result = await scan("hardened")
    # /, /about, /contact + the injectable endpoints linked from the index: /search, /item,
    # /download, /go (spec 006), /fetch, /webhook (spec 009), /ping, /greet (spec 011),
    # /set-lang, /reset, /resource (spec 012) and /dir, /xdoc, /page (spec 014) + the GET
    # /search?q= the crawler submits from the search form + /account (→ /login for an
    # anonymous scan) (spec 007 RF-05) + /guestbook (spec 008 RF-13) + /report, /banner, /rule
    # (spec 016) + /panel (spec 017) + /support (spec 018). The spec-013
    # /openapi.json + /api/* routes and the spec-014 /upload + /files routes are linked from
    # no page.
    assert result.metadata.pages_scanned == 25


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


async def test_command_injection_found_on_the_insecure_ping_endpoint(scan) -> None:
    """The ``/ping`` endpoint shells out — an active scan reports a CRITICAL command injection."""
    result = await scan("insecure", active=True)
    cmdi = [f for f in result.findings if f.check_id == "injection.cmdi.os"]
    assert cmdi, "expected an OS command-injection finding"
    assert any(f.location.param == "host" for f in cmdi)
    assert cmdi[0].severity.name == "CRITICAL"


async def test_ssti_found_on_the_insecure_greet_endpoint(scan) -> None:
    """The ``/greet`` endpoint concatenates into template source — an SSTI is reported."""
    result = await scan("insecure", active=True)
    ssti = [f for f in result.findings if f.check_id == "injection.ssti"]
    assert ssti, "expected a server-side template-injection finding"
    assert any(f.location.param == "name" for f in ssti)
    assert "Jinja" in ssti[0].title


async def test_hardened_ping_and_greet_report_no_rce(scan) -> None:
    """The hardened ``/ping`` validates its input and ``/greet`` renders data, so nothing fires."""
    result = await scan("hardened", active=True)
    assert not any(f.check_id in {"injection.cmdi.os", "injection.ssti"} for f in result.findings)


async def test_rce_scan_is_deterministic(scan) -> None:
    """Two active scans produce the same command-injection / SSTI finding fingerprints."""
    a = await scan("insecure", active=True)
    b = await scan("insecure", active=True)
    ids = {"injection.cmdi.os", "injection.ssti"}
    fa = sorted(f.fingerprint for f in a.findings if f.check_id in ids)
    fb = sorted(f.fingerprint for f in b.findings if f.check_id in ids)
    assert fa == fb and fa


async def test_expression_language_found_on_the_three_insecure_routes(scan) -> None:
    """SpEL (bare), OGNL (``%{}``) and sandboxed SpEL each get the dialect and severity earned."""
    result = await scan("insecure", active=True)
    el = {f.location.param: f for f in result.findings if f.check_id == "injection.el"}
    assert {"filter", "caption", "cond"} <= set(el), sorted(el)
    assert el["filter"].severity.name == "CRITICAL" and "SpEL" in el["filter"].title
    assert el["caption"].severity.name == "CRITICAL" and "OGNL" in el["caption"].title
    assert el["cond"].severity.name == "HIGH" and "SpEL" in el["cond"].title  # sandboxed
    assert all(f.location.method == "GET" for f in el.values())


async def test_an_el_proof_is_not_also_reported_as_ssti(scan) -> None:
    """The combined detector gives one finding per proof; ``/greet`` stays a Jinja2 ``ssti``."""
    result = await scan("insecure", active=True)
    ssti = {f.location.param for f in result.findings if f.check_id == "injection.ssti"}
    assert not ssti & {"filter", "caption", "cond"}
    assert "name" in ssti


async def test_hardened_profile_reports_no_expression_language(scan) -> None:
    """The hardened twins escape and never evaluate, so an Active scan finds nothing."""
    result = await scan("hardened", active=True)
    assert not any(f.check_id == "injection.el" for f in result.findings)


async def test_passive_scan_reports_no_expression_language(scan) -> None:
    """A Passive scan never runs the injection pass."""
    result = await scan("insecure")
    assert not any(f.check_id == "injection.el" for f in result.findings)


async def test_expression_language_scan_is_deterministic(scan) -> None:
    """Two active scans give the same ``injection.el`` finding fingerprints."""
    a = await scan("insecure", active=True)
    b = await scan("insecure", active=True)
    fa = sorted(f.fingerprint for f in a.findings if f.check_id == "injection.el")
    fb = sorted(f.fingerprint for f in b.findings if f.check_id == "injection.el")
    assert fa == fb and fa


async def test_crlf_injection_found_on_the_insecure_set_lang_endpoint(scan) -> None:
    """The ``/set-lang`` endpoint writes ``lang`` into a header unfiltered — a HIGH CRLF hit."""
    result = await scan("insecure", active=True)
    crlf = [f for f in result.findings if f.check_id == "injection.crlf"]
    assert crlf, "expected a CRLF-injection finding"
    assert any(f.location.param == "lang" for f in crlf)
    assert crlf[0].severity.name == "HIGH"


async def test_host_header_injection_found_on_the_insecure_reset_page(scan) -> None:
    """The ``/reset`` link is built from the request Host header — a host-header finding."""
    result = await scan("insecure", active=True)
    hh = [f for f in result.findings if f.check_id == "injection.host-header"]
    assert hh, "expected a host-header-injection finding"
    assert any(
        "Forwarded-Host" in (f.location.param or "") or f.location.param == "Host" for f in hh
    )


async def test_trace_and_dangerous_methods_reported_on_the_insecure_profile(scan) -> None:
    """``/resource`` advertises TRACE + PUT + DELETE and echoes TRACE — a methods finding."""
    result = await scan("insecure", active=True)
    methods = [f for f in result.findings if f.check_id == "http.methods.unsafe"]
    assert methods, "expected an unsafe-HTTP-methods finding"
    assert any("/resource" in (f.location.url or "") for f in methods)


async def test_xxe_found_only_with_the_opt_in(scan) -> None:
    """``/api/xml`` resolves entities, but the XXE step runs only with ``--xxe``."""
    without = await scan("insecure", active=True)
    assert not any(f.check_id == "injection.xxe" for f in without.findings)
    with_optin = await scan("insecure", active=True, xxe=True)
    xxe = [f for f in with_optin.findings if f.check_id == "injection.xxe"]
    assert xxe and xxe[0].severity.name == "HIGH"


async def test_hardened_profile_reports_no_envelope_findings(scan) -> None:
    """The hardened profile validates lang / builds a fixed reset URL / limits methods."""
    result = await scan("hardened", active=True, xxe=True)
    assert not any(
        f.check_id
        in {"injection.crlf", "injection.host-header", "http.methods.unsafe", "injection.xxe"}
        for f in result.findings
    )


async def test_envelope_scan_is_deterministic(scan) -> None:
    """Two active scans produce the same request-envelope finding fingerprints."""
    ids = {"injection.crlf", "injection.host-header", "http.methods.unsafe"}
    fa = sorted(
        f.fingerprint for f in (await scan("insecure", active=True)).findings if f.check_id in ids
    )
    fb = sorted(
        f.fingerprint for f in (await scan("insecure", active=True)).findings if f.check_id in ids
    )
    assert fa == fb and fa


async def test_passive_scan_issues_no_crafted_request(scan) -> None:
    """A passive scan sends no payload: no ``SLEEP`` / ``etc/passwd`` / ``OPTIONS`` / ``TRACE``."""
    result = await scan("insecure", active=False)
    assert not any(f.check_id.startswith("injection.") for f in result.findings)
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    assert all("SLEEP" not in entry and "etc/passwd" not in entry for entry in log)
    assert not any(entry.startswith(("OPTIONS ", "TRACE ")) for entry in log)


async def test_hardened_profile_active_reports_nothing(scan) -> None:
    """The hardened profile reports no injection findings under an active scan."""
    result = await scan("hardened", active=True)
    assert not any(f.check_id.startswith("injection.") for f in result.findings)


# ---------------------------------------------------------------------------
# Auth width and API surface (spec 013)
# ---------------------------------------------------------------------------

_OPENAPI_URL = "http://demo.test/openapi.json"


async def test_openapi_import_reaches_an_unlinked_endpoint_and_fuzzes_it(scan) -> None:
    """``--openapi`` seeds ``/api/find`` (linked from nowhere) and the XSS detector hits it."""
    result = await scan("insecure", active=True, openapi=_OPENAPI_URL)
    xss = [
        f
        for f in result.findings
        if f.check_id == "injection.xss.reflected" and "/api/find" in (f.location.url or "")
    ]
    assert xss and xss[0].location.param == "q"
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    assert any(entry.startswith("GET /api/find?") for entry in log)


async def test_content_and_leakage_checks_fire_on_the_insecure_index(scan) -> None:
    """The passive spec-013 checks flag the insecure index; mixed content stays quiet on HTTP."""
    result = await scan("insecure")
    reported = {f.check_id for f in result.findings}
    assert "content.sri.missing" in reported
    assert "disclosure.session-id-in-url" in reported
    assert "disclosure.private-ip" in reported
    assert "content.mixed" not in reported
    session = next(f for f in result.findings if f.check_id == "disclosure.session-id-in-url")
    assert "WV013SECRETTOKEN" not in " ".join(e.content for e in session.evidence)


async def test_a_bearer_token_never_appears_in_the_report(scan) -> None:
    """A ``--header`` bearer token reaches the target but not the rendered JSON report."""
    result = await scan(
        "insecure",
        active=True,
        openapi=_OPENAPI_URL,
        headers=["Authorization: Bearer wv-secret-123"],
    )
    rendered = get_reporter("json").render(result)
    assert "wv-secret-123" not in rendered  # never leaves, even via the /resource TRACE echo
    assert result.metadata.authenticated is True


async def test_openapi_scan_is_deterministic(scan) -> None:
    """Two active scans with the same import produce the same finding fingerprints.

    The time-delay detectors are off here (issue #58): they decide on wall-clock response
    times, so a stalled request on a loaded runner made one of the two scans miss a finding.
    This test is about fingerprint stability; the time-based detectors have their own
    coverage (`test_insecure_profile_active_finds_every_injection` and the unit tests).
    """
    a = await scan("insecure", active=True, openapi=_OPENAPI_URL, time_based=False)
    b = await scan("insecure", active=True, openapi=_OPENAPI_URL, time_based=False)
    assert a.findings
    _assert_same_findings(a, b)


async def test_the_login_form_is_never_fuzzed(scan) -> None:
    """The login form is never submitted with a payload, even during an active scan."""
    await scan("insecure", active=True)
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    # The crawler may GET /login (it is the redirect target of /account), but the login
    # form is never submitted with a payload.
    assert not any(entry.startswith("POST /login") for entry in log)
    assert not any(entry.startswith("GET /login?") and entry != "GET /login?" for entry in log)


async def test_active_injection_scan_is_deterministic(scan) -> None:
    """Two active scans of the insecure profile produce the same finding set.

    Time-delay detectors off, for the reason in `test_openapi_scan_is_deterministic`.
    """
    first = await scan("insecure", active=True, time_based=False)
    second = await scan("insecure", active=True, time_based=False)
    _assert_same_findings(first, second)


def test_same_findings_helper_accepts_two_equal_scans() -> None:
    """The same findings in a different order are not a difference."""
    xss = make_finding(check_id="injection.xss.reflected", param="q", dedup_key="a")
    sqli = make_finding(check_id="injection.sqli.error", param="id", dedup_key="b")
    _assert_same_findings(make_result(xss, sqli), make_result(sqli, xss))


def test_same_findings_helper_names_what_only_one_scan_has() -> None:
    """A mismatch lists the check, location and param, not just a bare fingerprint (issue #58)."""
    kept = make_finding(check_id="injection.xss.reflected", param="q", dedup_key="a")
    extra = make_finding(
        check_id="injection.sqli.time-based",
        severity=Severity.HIGH,
        url="http://demo.test/item",
        param="id",
        dedup_key="b",
    )
    with pytest.raises(AssertionError) as caught:
        _assert_same_findings(make_result(kept, extra), make_result(kept))
    message = str(caught.value)
    assert "only in the first" in message
    assert "injection.sqli.time-based" in message
    assert "http://demo.test/item" in message
    assert "param=id" in message
    assert "injection.xss.reflected" not in message  # the shared finding is not blamed


# ---------------------------------------------------------------------------
# File upload + LDAP / XPath / SSI (spec 014)
# ---------------------------------------------------------------------------


async def test_ldap_xpath_ssi_detectors_fire_on_the_insecure_profile(scan) -> None:
    """An active scan of the insecure profile finds the three spec-014 injection sinks."""
    result = await scan("insecure", active=True)
    reported = {f.check_id for f in result.findings}
    assert "injection.ldap" in reported
    assert "injection.xpath" in reported
    assert "injection.ssi" in reported


async def test_file_upload_pass_finds_the_unrestricted_endpoint_only_with_the_opt_in(scan) -> None:
    """``--file-upload`` uploads markers through ``/upload`` and proves several outcomes."""
    without = await scan("insecure", active=True)
    assert not any(f.check_id == "upload.unrestricted" for f in without.findings)
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    assert not any(entry.startswith("POST /upload") for entry in log)

    result = await scan("insecure", active=True, file_upload=True)
    uploads = [f for f in result.findings if f.check_id == "upload.unrestricted"]
    outcomes = {f.location.method for f in uploads}
    assert uploads
    severities = {f.severity.name for f in uploads}
    assert "CRITICAL" in severities or "HIGH" in severities
    assert "PUT" in outcomes or "POST" in outcomes


async def test_hardened_profile_reports_no_spec_014_findings(scan) -> None:
    """The hardened profile yields zero LDAP / XPath / SSI / upload findings."""
    result = await scan("hardened", active=True, file_upload=True)
    assert not any(
        f.check_id in {"injection.ldap", "injection.xpath", "injection.ssi", "upload.unrestricted"}
        for f in result.findings
    )


async def test_passive_scan_sends_no_spec_014_payloads(scan) -> None:
    """A passive scan uploads nothing and sends no LDAP / XPath / SSI payload or PUT."""
    await scan("insecure", file_upload=True)  # opt-in ignored: passive
    log = scan.holder["app"].state.requests  # type: ignore[attr-defined]
    assert not any(entry.startswith(("POST /upload", "PUT ")) for entry in log)
    assert not any(")(" in entry or "1'='1" in entry or "%23echo" in entry for entry in log)


async def test_file_upload_scan_is_deterministic(scan) -> None:
    """Two active ``--file-upload`` scans produce the same upload finding fingerprints."""
    a = await scan("insecure", active=True, file_upload=True)
    b = await scan("insecure", active=True, file_upload=True)
    fa = sorted(f.fingerprint for f in a.findings if f.check_id == "upload.unrestricted")
    fb = sorted(f.fingerprint for f in b.findings if f.check_id == "upload.unrestricted")
    assert fa == fb and fa


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
    profile = [f for f in csrf if f.location.url.endswith("/profile")]
    assert len(profile) == 1
    assert profile[0].location.method == "POST"
    # spec 017: the /panel page adds the tokenless /newsletter form, flagged the same way.
    assert {f.location.url.rsplit("/", 1)[1] for f in csrf} == {"profile", "newsletter"}


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


# ---------------------------------------------------------------------------
# Active CSRF confirmation (spec 017)
# ---------------------------------------------------------------------------


def _csrf_confirmed(result: ScanResult) -> set[str]:
    """
    Args:
        result (ScanResult): A completed scan.

    Returns:
        set[str]: The last path segment of every form ``csrf.form.token-not-enforced``
            reported.
    """
    return {
        f.location.url.rsplit("/", 1)[1]
        for f in result.findings
        if f.check_id == "csrf.form.token-not-enforced"
    }


def _csrf_writes(scan_holder: dict[str, object]) -> list[tuple[str, bool, str, str]]:
    """
    Args:
        scan_holder (dict[str, object]): ``scan.holder`` — the app the scan ran against.

    Returns:
        list[tuple[str, bool, str, str]]: The ``csrf_log`` entries the CSRF pass caused (the
            ones carrying its ``wvcsrf`` sentinel), as ``(route, accepted, Origin, value)``.
    """
    app = scan_holder["app"]
    return [entry for entry in app.state.csrf_log if "wvcsrf" in entry[3]]  # type: ignore[attr-defined]


async def test_csrf_confirmation_flags_the_unenforced_forms_only(scan) -> None:
    """Insecure + ``--confirm-csrf``: the no-token and ignored-token forms are confirmed."""
    result = await scan("insecure", active=True, confirm_csrf=True, time_based=False)
    confirmed = _csrf_confirmed(result)
    assert {"newsletter", "settings"} <= confirmed
    assert not {"transfer", "prefs"} & confirmed  # token enforced / Origin checked
    assert any(w.startswith("CSRF confirmation:") and "confirmed" in w for w in result.warnings)
    for finding in result.findings:
        if finding.check_id != "csrf.form.token-not-enforced":
            continue
        assert finding.location.method == "POST"
        labels = {item.label: item.content for item in finding.evidence}
        assert labels["replay"] in {"token removed", "token altered", "no token field"}
    # one proof, one finding: the passive finding yields to the confirmation
    passive = {
        f.location.url.rsplit("/", 1)[1]
        for f in result.findings
        if f.check_id == "csrf.form.no-token"
    }
    assert not passive & confirmed
    # the replays carried a foreign Origin; the controls carried the target's own
    writes = _csrf_writes(scan.holder)  # type: ignore[arg-type]
    assert any(origin == "https://webvigil.invalid" for _, _, origin, _ in writes)
    refused = {route for route, accepted, origin, _ in writes if not accepted}
    assert "prefs" in refused and "transfer" in refused


async def test_csrf_confirmation_stops_at_the_first_confirming_replay(scan) -> None:
    """A confirmed form is written to twice at most: the control and one replay."""
    await scan("insecure", active=True, confirm_csrf=True, time_based=False)
    writes = _csrf_writes(scan.holder)  # type: ignore[arg-type]
    assert sum(1 for route, *_ in writes if route == "settings") == 2
    assert sum(1 for route, *_ in writes if route == "newsletter") == 2


async def test_csrf_confirmation_not_run_without_the_opt_in(scan) -> None:
    """An active scan without ``--confirm-csrf`` submits nothing carrying the pass's sentinel."""
    result = await scan("insecure", active=True, time_based=False)
    assert _csrf_confirmed(result) == set()
    assert _csrf_writes(scan.holder) == []  # type: ignore[arg-type]
    assert not any(w.startswith("CSRF confirmation:") for w in result.warnings)
    # the passive finding for the tokenless form is untouched
    assert any(
        f.check_id == "csrf.form.no-token" and f.location.url.endswith("/newsletter")
        for f in result.findings
    )


async def test_csrf_confirmation_passive_scan_does_nothing(scan) -> None:
    """A passive scan makes no crafted POST to the panel routes."""
    result = await scan("insecure")
    assert _csrf_confirmed(result) == set()
    assert scan.holder["app"].state.csrf_log == []  # type: ignore[attr-defined]


async def test_hardened_profile_reports_no_unenforced_csrf(scan) -> None:
    """Every token the hardened profile serves is enforced: the pass confirms nothing."""
    result = await scan("hardened", active=True, confirm_csrf=True, time_based=False)
    assert _csrf_confirmed(result) == set()
    assert not any(f.check_id.startswith("csrf.") for f in result.findings)
    assert any(w.startswith("CSRF confirmation:") and "0 confirmed" in w for w in result.warnings)
    writes = _csrf_writes(scan.holder)  # type: ignore[arg-type]
    replays = [
        accepted for _, accepted, origin, _ in writes if origin == "https://webvigil.invalid"
    ]
    assert replays and not any(replays)  # every cross-site replay was refused
    assert any(
        accepted for _, accepted, origin, _ in writes if origin != "https://webvigil.invalid"
    )


async def test_csrf_confirmation_is_deterministic(scan) -> None:
    """Two confirmation scans of the insecure profile confirm the same forms."""

    async def _once() -> set[str]:
        return _csrf_confirmed(
            await scan("insecure", active=True, confirm_csrf=True, time_based=False)
        )

    assert await _once() == await _once()


# ---------------------------------------------------------------------------
# The crawler's POST phase (spec 018)
# ---------------------------------------------------------------------------

_NOTES_DOC = {
    "openapi": "3.0.0",
    "info": {"title": "notes", "version": "1"},
    "paths": {
        "/api/notes": {
            "post": {
                "operationId": "createNote",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"text": {"type": "string"}},
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "ok"}},
            }
        }
    },
}


def _crawl_posts(holder: dict[str, object]) -> list[tuple[str, str, dict[str, object]]]:
    """
    Args:
        holder (dict[str, object]): ``scan.holder`` — the app the scan ran against.

    Returns:
        list[tuple[str, str, dict[str, object]]]: The ``post_log`` entries the crawler's POST
            phase caused: the ones carrying its ``wvcrawl`` marker, plus the JSON notes post
            (the importer's synthesised body has no marker, and nothing else posts JSON).
    """
    app = holder["app"]
    return [
        entry
        for entry in app.state.post_log  # type: ignore[attr-defined]
        if entry[1] == "application/json"
        or any(str(value).startswith("wvcrawl") for value in entry[2].values())
    ]


def _notes_doc(tmp_path: Path) -> str:
    """
    Args:
        tmp_path (Path): A temporary directory.

    Returns:
        str: The path of a one-operation OpenAPI document with a JSON ``POST /api/notes``.
    """
    import json

    path = tmp_path / "notes.json"
    path.write_text(json.dumps(_NOTES_DOC), "utf-8")
    return str(path)


async def test_post_crawl_reaches_what_only_a_post_leads_to(scan, tmp_path) -> None:
    """Insecure + ``--submit-post-forms``: the answers become pages and their links are followed."""
    result = await scan(
        "insecure", active=True, post_forms=True, time_based=False, openapi=_notes_doc(tmp_path)
    )
    app = scan.holder["app"]
    posts = _crawl_posts(scan.holder)  # type: ignore[arg-type]
    assert {"ticket", "callback", "feedback", "notes"} <= {entry[0] for entry in posts}
    # the answers' links were followed: the status page is linked only from the ticket answer, and
    # the received page is reachable only through the callback redirect
    log = app.state.requests  # type: ignore[attr-defined]
    assert any(line.startswith("GET /support/status") for line in log)
    # the multipart and JSON bodies arrived as such
    kinds = {entry[0]: entry[1] for entry in posts}
    assert kinds["callback"].startswith("multipart/form-data")
    assert kinds["notes"] == "application/json"
    # defaults and the marker only: no payload
    for route, _, fields in posts:
        if route == "notes":
            continue
        assert all(
            str(v) in {"supporttok", "xml", "1"} or str(v).startswith("wvcrawl")
            for v in fields.values()
        ), (route, fields)
    # the passive checks read the page only a POST reaches
    feedback = {f.check_id for f in result.findings if f.location.url.endswith("/support/feedback")}
    assert {"disclosure.debug.error-page", "content.sri.missing"} <= feedback
    tally = next(w for w in result.warnings if w.startswith("POST crawl:"))
    assert "API operation" in tally and "0 not submitted" in tally
    # the API operation's URL is not a form action: no pass re-requested it with GET
    assert not any(line.startswith("GET /api/notes") for line in log)


async def test_post_crawl_not_run_without_the_switch_or_in_passive_mode(scan) -> None:
    """No crawler POST without the switch; with it in a Passive scan only a warning appears."""
    passive = await scan("insecure", post_forms=True)
    assert _crawl_posts(scan.holder) == []  # type: ignore[arg-type]
    assert any("POST crawling requires --mode active" in w for w in passive.warnings)
    assert not any(w.startswith("POST crawl:") for w in passive.warnings)
    active = await scan("insecure", active=True, time_based=False)
    assert _crawl_posts(scan.holder) == []  # type: ignore[arg-type]
    assert not any(w.startswith("POST crawl:") for w in active.warnings)


async def test_hardened_profile_post_crawl_reports_nothing(scan) -> None:
    """The hardened answers are reached and read, and nothing is reported."""
    result = await scan("hardened", active=True, post_forms=True, time_based=False)
    assert {"ticket", "callback", "feedback"} <= {
        entry[0] for entry in _crawl_posts(scan.holder)  # type: ignore[arg-type]
    }
    assert result.findings == ()
    assert result.errors == ()


async def test_post_crawl_is_deterministic(scan) -> None:
    """Two POST-crawl scans of the insecure profile report the same findings."""

    async def _once() -> set[tuple[str, str]]:
        result = await scan("insecure", active=True, post_forms=True, time_based=False)
        return {(f.check_id, f.fingerprint) for f in result.findings}

    assert await _once() == await _once()
