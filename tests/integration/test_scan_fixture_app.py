"""
End-to-end: insecure profile reports the expected findings, hardened reports none — RF-27.

Runs the real :class:`Orchestrator` against the in-process fixture app
(``tests/fixtures/app.py``) — ``HttpClient`` is monkeypatched onto an
``ASGITransport`` so a full scan (crawl, checks, active passes) happens with no
sockets.

**Scans are shared.** A full Active scan of the fixture takes minutes, so the ``scan`` fixture
runs each distinct configuration **once per test session** and hands every test that only
inspects a result the same one (issue #101: the suite used to run ``("insecure", active=True)``
23 times). The few configurations that matter are named below:

* ``scan("insecure")`` — the passive baseline;
* ``scan("insecure", **_ACTIVE)`` — the default Active scan, with the time-delay detectors on;
* ``scan(profile, **_full(profile))`` — **every** switch on at once (stored XSS, XXE, file upload,
  CSRF confirmation, POST crawl, an OpenAPI import, a HAR import, an automated login, session-id
  sampling, the logout test and a bearer header),
  with the time-delay detectors off (issue #58: they decide on wall-clock time). The hardened twin
  of that scan is the "reports nothing" check for every spec at once;
* ``scan("hardened", ..., login=True, session_ttl=2)`` — the one extra scan of spec 019: the
  session expires under the crawl, so the login must be repeated.

``scan.fresh(...)`` bypasses the cache — a determinism test needs a second, independent run.
``scan.holder["app"]`` is the app of the scan the last call returned, so a test can read
``app.state.requests`` / ``csrf_log`` / ``post_log`` right after the call.
``_OSV_JQUERY_RECORD`` + ``_osv_up`` / ``_osv_down`` stub the OSV.dev API.
"""

from __future__ import annotations

import functools
import json
import re

import httpx
import pytest
from starlette.applications import Starlette

from tests.fixtures.app import SIGNIN_PASSWORD, SIGNIN_USER, make_app
from tests.support import make_finding, make_result
from webvigil.auth.login import Credentials
from webvigil.checks.deps.osv import OsvProvider
from webvigil.core import orchestrator as orch_mod
from webvigil.core.config import ScanConfig
from webvigil.core.findings import Finding, Severity
from webvigil.core.orchestrator import Orchestrator
from webvigil.core.result import LoginSummary, ScanResult
from webvigil.http.client import HttpClient
from webvigil.reporting import get_reporter

_TARGET = "http://demo.test/"
_OPENAPI_URL = "http://demo.test/openapi.json"
# The fixture app is plain HTTP; TLS findings are covered by the socket-based unit tests.
_DISABLED = ["tls.https"]

# spec 021: the HAR the full scan imports. Written once per session by ``_har_file``; the secret
# strings below must never come out of any report (RF-07, RNF-05).
_HAR_SECRETS = ("HARSECRETCOOKIE", "HARSECRETBEARER", "HARSECRETTOKEN", "HARSECRETNOTE")
_HAR: dict[str, str] = {}

# The default Active scan: the only one with the time-delay detectors on.
_ACTIVE = {"active": True}
_BEARER = "Authorization: Bearer wv-secret-123"
# Every opt-in switch, for the scans that need all of them on.
_OPT_INS = {
    "stored_xss": True,
    "xxe": True,
    "file_upload": True,
    "confirm_csrf": True,
    "post_forms": True,
}


def _full(profile: str) -> dict[str, object]:
    """
    Args:
        profile (str): ``"insecure"`` or ``"hardened"``.

    Returns:
        dict[str, object]: The keyword arguments of the one scan that turns everything on: Active,
            every opt-in, an OpenAPI import, an automated login (spec 019; it sets the session
            cookie the profile expects) and a bearer header, with the time-delay detectors off.
    """
    return {
        "active": True,
        "time_based": False,
        "openapi": _OPENAPI_URL,
        "har": _HAR["path"],
        "login": True,
        "sample_sessions": True,
        "test_logout": True,
        "headers": [_BEARER],
        **_OPT_INS,
    }


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


# One finished scan per distinct configuration, for the whole test session (issue #101).
_SCANS: dict[tuple[object, ...], tuple[ScanResult, Starlette]] = {}


def _har_entry(
    url: str,
    method: str = "GET",
    *,
    rtype: str = "xhr",
    headers: list[dict[str, str]] | None = None,
    post: dict[str, object] | None = None,
) -> dict[str, object]:
    """
    Args:
        url (str): The recorded request URL.
        method (str): The method. Defaults to ``"GET"``.
        rtype (str): Chrome's ``_resourceType``. Defaults to ``"xhr"``.
        headers (list[dict[str, str]] | None): Recorded request headers.
        post (dict[str, object] | None): The ``postData`` object.

    Returns:
        dict[str, object]: A HAR entry.
    """
    request: dict[str, object] = {"method": method, "url": url, "headers": headers or []}
    if post is not None:
        request["postData"] = post
    return {"_resourceType": rtype, "request": request, "response": {"status": 200}}


@pytest.fixture(scope="session", autouse=True)
def _har_file(tmp_path_factory: pytest.TempPathFactory) -> None:
    """
    Write the HAR the full scan imports (spec 021), once per session, and record its path.

    It names a GET route and a JSON POST route that no page links to, and carries every kind of
    entry the importer must leave alone: a foreign host, a static asset, a ``DELETE``, a login, and
    recorded credentials (a ``Cookie``, an ``Authorization`` header, a ``?token=``, a JSON value).

    Args:
        tmp_path_factory (pytest.TempPathFactory): pytest's session-scoped temp directory factory.
    """
    session_headers = [
        {"name": "Cookie", "value": "sid=HARSECRETCOOKIE"},
        {"name": "Authorization", "value": "Bearer HARSECRETBEARER"},
    ]
    entries = [
        _har_entry("http://demo.test/spa/items?name=widget"),
        _har_entry(
            "http://demo.test/spa/items?name=widget&tab=1&token=HARSECRETTOKEN",
            headers=session_headers,
        ),
        _har_entry(
            "http://demo.test/spa/notes",
            "POST",
            post={"mimeType": "application/json", "text": json.dumps({"text": "HARSECRETNOTE"})},
        ),
        _har_entry("https://cdn.example.net/foreign/only-on-cdn"),
        _har_entry("http://demo.test/static/app.js", rtype="script"),
        _har_entry("http://demo.test/spa/items/1", "DELETE"),
        _har_entry("http://demo.test/spa/session/login", "POST"),
    ]
    path = tmp_path_factory.mktemp("har") / "traffic.har"
    path.write_text(json.dumps({"log": {"version": "1.2", "entries": entries}}), "utf-8")
    _HAR["path"] = str(path)


@pytest.fixture
def scan(monkeypatch: pytest.MonkeyPatch):
    """Yield an ``async`` runner that scans the fixture app for a given profile.

    The returned callable takes the profile name plus optional ``probe`` / ``active`` /
    ``cookies`` / ``headers`` / ``login`` / ``session_ttl`` / ``sample_sessions`` /
    ``test_logout`` / ``stored_xss`` / ``xxe`` /
    ``file_upload`` / ``confirm_csrf`` / ``post_forms`` / ``openapi`` / ``har`` / ``osv_online`` /
    ``osv_up`` / ``time_based`` switches,
    assembles the :class:`ScanConfig`, points the engine's HTTP client (and, for OSV, its
    provider) at in-process transports, runs the scan **the first time that configuration is
    asked for in the session**, and returns the :class:`ScanResult`; a later call with the same
    configuration returns the same result. ``scan.fresh(...)`` always runs a new scan. The app
    that produced the result is stashed on ``scan.holder`` so a test can read its
    ``app.state``. ``time_based=False`` turns off the time-delay SQLi and command-injection
    detectors of an active scan: they decide on wall-clock response times, which a loaded
    runner can distort. An opt-in switch outside Active Mode reaches the engine, which must
    ignore it and warn.
    """
    holder: dict[str, object] = {}

    async def _execute(
        profile: str,
        *,
        probe: bool,
        active: bool,
        cookies: list[str] | None,
        headers: list[str] | None,
        login: bool,
        session_ttl: int | None,
        sample_sessions: bool,
        test_logout: bool,
        stored_xss: bool,
        xxe: bool,
        file_upload: bool,
        confirm_csrf: bool,
        post_forms: bool,
        openapi: str | None,
        har: str | None,
        osv_online: bool,
        osv_up: bool,
        time_based: bool,
    ) -> tuple[ScanResult, Starlette]:
        app = make_app(profile, session_ttl=session_ttl)
        transport = httpx.ASGITransport(app=app)
        monkeypatch.setattr(
            orch_mod, "HttpClient", functools.partial(HttpClient, transport=transport)
        )
        raw: dict[str, object] = {
            "checks": {"disabled": _DISABLED},
            "disclosure": {"probe": probe},
            "injection": {
                "stored_xss": stored_xss,
                "xxe": xxe,
                "file_upload": file_upload,
                "csrf_confirm": confirm_csrf,
            },
            "scan": {"submit_post_forms": post_forms},
        }
        if active:
            # A wider page budget for the stored-XSS re-crawl: an active scan of the insecure
            # profile fuzzes ~13 injection points plus the forms of every spec, and every
            # POST-form payload leaves a guestbook entry the Phase-B re-crawl walks past to
            # reach the marker's own entry. The request budget is raised past the model default
            # so the slow sqli-time / stored-XSS phases still run on this unusually dense fixture.
            # The scan with every switch on needs about twice the old 1200: the guard in
            # ``test_the_full_scan_runs_clean_and_within_budget`` caught it starving.
            raw["scan"] = {**raw["scan"], "mode": "active", "max_pages": 90}  # type: ignore[dict-item]
            raw["active"] = {"authorized_by": "integration test"}
            raw["injection"] = {
                **raw["injection"],  # type: ignore[dict-item]
                "time_based_sqli": time_based,
                "time_based_cmdi": time_based,
                "time_based_delay_s": 2,
                "request_budget": 2400,
                # keep the spec-012 envelope pass small for the fixture; the sample takes the
                # entry, then every form action, then the other pages, so the form actions of
                # specs 017 (/panel, four) and 018 (/support, three) pushed /reset and
                # /resource out of the earlier samples of 20 and then 24
                "envelope_url_sample": 30,
                "envelope_budget": 180,
            }
        if openapi is not None:
            raw["scan"] = {**raw["scan"], "openapi": openapi}  # type: ignore[dict-item]
        if har is not None:
            raw["scan"] = {**raw["scan"], "har": har}  # type: ignore[dict-item]
        if cookies is not None or headers is not None:
            raw["auth"] = {"cookies": cookies or [], "headers": headers or []}
        if sample_sessions or test_logout:
            raw["session"] = {"sample_ids": sample_sessions, "test_logout": test_logout}
        if login:
            # the password comes in as Credentials, never through the config (spec 019, ADR-8)
            raw["auth"] = {
                **raw.get("auth", {}),  # type: ignore[dict-item]
                "login": {
                    "url": f"{_TARGET}signin",
                    "username": SIGNIN_USER,
                    "max_relogins": 10,
                },
            }
        if osv_online:
            raw["deps"] = {"osv_online": True, "osv_base_url": "http://osv.test"}
            handler = _osv_up if osv_up else _osv_down
            monkeypatch.setattr(
                orch_mod,
                "OsvProvider",
                functools.partial(OsvProvider, transport=httpx.MockTransport(handler)),
            )
        credentials = Credentials(SIGNIN_USER, SIGNIN_PASSWORD) if login else None
        result = await Orchestrator(ScanConfig.model_validate(raw), credentials=credentials).run(
            _TARGET
        )
        return result, app

    async def _run(
        profile: str,
        *,
        fresh: bool = False,
        probe: bool = False,
        active: bool = False,
        cookies: list[str] | None = None,
        headers: list[str] | None = None,
        login: bool = False,
        session_ttl: int | None = None,
        sample_sessions: bool = False,
        test_logout: bool = False,
        stored_xss: bool = False,
        xxe: bool = False,
        file_upload: bool = False,
        confirm_csrf: bool = False,
        post_forms: bool = False,
        openapi: str | None = None,
        har: str | None = None,
        osv_online: bool = False,
        osv_up: bool = True,
        time_based: bool = True,
    ) -> ScanResult:
        options = {
            "probe": probe,
            "active": active,
            "cookies": cookies,
            "headers": headers,
            "login": login,
            "session_ttl": session_ttl,
            "sample_sessions": sample_sessions,
            "test_logout": test_logout,
            "stored_xss": stored_xss,
            "xxe": xxe,
            "file_upload": file_upload,
            "confirm_csrf": confirm_csrf,
            "post_forms": post_forms,
            "openapi": openapi,
            "har": har,
            "osv_online": osv_online,
            "osv_up": osv_up,
            "time_based": time_based,
        }
        key = (
            profile,
            *(tuple(v) if isinstance(v, list) else v for v in options.values()),
        )
        if not fresh and key in _SCANS:
            result, app = _SCANS[key]
        else:
            result, app = await _execute(profile, **options)  # type: ignore[arg-type]
            if not fresh:
                _SCANS[key] = (result, app)
        holder["app"] = app
        return result

    _run.holder = holder  # type: ignore[attr-defined]
    _run.fresh = functools.partial(_run, fresh=True)  # type: ignore[attr-defined]
    return _run


def _log(scan) -> list[str]:
    """
    Args:
        scan: The ``scan`` fixture.

    Returns:
        list[str]: The request lines (``"<method> <path>?<query>"``) the app behind the last
            scan received.
    """
    return scan.holder["app"].state.requests  # type: ignore[no-any-return]


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


async def test_osv_not_queried_without_the_opt_in(scan) -> None:
    """Without ``osv_online`` the jQuery finding carries no osv.dev reference."""
    result = await scan("insecure")
    finding = next(f for f in result.findings if f.check_id == "deps.js.vulnerable-library")
    assert not any("osv.dev/vulnerability/" in reference for reference in finding.references)


async def test_insecure_profile_passive_disclosure_without_probe(scan) -> None:
    """Without ``--probe`` only the passive disclosure checks fire (error page, dir listing)."""
    result = await scan("insecure")
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
# A passive scan sends nothing crafted, whatever opt-in is set (specs 006-018)
# ---------------------------------------------------------------------------


async def test_passive_scan_sends_nothing_crafted(scan) -> None:
    """A passive scan runs no injection pass and no POST: no payload, no upload, no replay."""
    result = await scan("insecure")
    assert not any(f.check_id.startswith(("injection.", "upload.")) for f in result.findings)
    assert not any(f.check_id == "csrf.form.token-not-enforced" for f in result.findings)
    log = _log(scan)
    assert all("SLEEP" not in entry and "etc/passwd" not in entry for entry in log)
    assert not any(entry.startswith(("OPTIONS ", "TRACE ", "PUT ", "POST ")) for entry in log)
    assert not any(")(" in entry or "1'='1" in entry or "%23echo" in entry for entry in log)
    app = scan.holder["app"]
    assert app.state.csrf_log == [] and app.state.post_log == []  # type: ignore[attr-defined]


async def test_passive_scan_ignores_every_opt_in_and_says_so(scan) -> None:
    """With every opt-in set but no ``--mode active`` the engine sends nothing and warns."""
    result = await scan("insecure", **_OPT_INS)
    for opt_in in (
        "stored-XSS testing requires --mode active",
        "file-upload testing requires --mode active",
        "CSRF confirmation requires --mode active",
        "POST crawling requires --mode active",
    ):
        assert any(opt_in in warning for warning in result.warnings), opt_in
    assert not any(w.startswith(("POST crawl:", "CSRF confirmation:")) for w in result.warnings)
    log = _log(scan)
    assert not any(entry.startswith(("POST ", "PUT ")) for entry in log)
    app = scan.holder["app"]
    assert app.state.csrf_log == [] and app.state.post_log == []  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Active injection (specs 006 / 009 / 011 / 012 / 014 / 016) — the default Active scan
# ---------------------------------------------------------------------------


async def test_insecure_profile_active_finds_every_injection(scan) -> None:
    """An active scan finds every seeded injection kind (XSS, SQLi, traversal, open redirect)."""
    result = await scan("insecure", **_ACTIVE)
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
    result = await scan("insecure", **_ACTIVE)
    meta = [f for f in result.findings if f.check_id == "injection.ssrf.metadata"]
    assert meta, "expected a cloud-metadata SSRF finding"
    finding = meta[0]
    assert finding.location.param == "url"
    assert finding.severity.name == "CRITICAL"
    assert "AccessKeyId" in " ".join(e.content for e in finding.evidence)


async def test_ssrf_internal_found_on_the_insecure_webhook_endpoint(scan) -> None:
    """The ``/webhook`` endpoint yields an internal-resource SSRF finding on ``callback``."""
    result = await scan("insecure", **_ACTIVE)
    internal = [f for f in result.findings if f.check_id == "injection.ssrf.internal"]
    assert internal, "expected an internal-resource SSRF finding"
    assert any(f.location.param == "callback" for f in internal)


async def test_command_injection_found_on_the_insecure_ping_endpoint(scan) -> None:
    """The ``/ping`` endpoint shells out — an active scan reports a CRITICAL command injection."""
    result = await scan("insecure", **_ACTIVE)
    cmdi = [f for f in result.findings if f.check_id == "injection.cmdi.os"]
    assert cmdi, "expected an OS command-injection finding"
    assert any(f.location.param == "host" for f in cmdi)
    assert cmdi[0].severity.name == "CRITICAL"


async def test_ssti_found_on_the_insecure_greet_endpoint(scan) -> None:
    """The ``/greet`` endpoint concatenates into template source — an SSTI is reported."""
    result = await scan("insecure", **_ACTIVE)
    ssti = [f for f in result.findings if f.check_id == "injection.ssti"]
    assert ssti, "expected a server-side template-injection finding"
    assert any(f.location.param == "name" for f in ssti)
    assert "Jinja" in ssti[0].title


async def test_expression_language_found_on_the_three_insecure_routes(scan) -> None:
    """SpEL (bare), OGNL (``%{}``) and sandboxed SpEL each get the dialect and severity earned."""
    result = await scan("insecure", **_ACTIVE)
    el = {f.location.param: f for f in result.findings if f.check_id == "injection.el"}
    assert {"filter", "caption", "cond"} <= set(el), sorted(el)
    assert el["filter"].severity.name == "CRITICAL" and "SpEL" in el["filter"].title
    assert el["caption"].severity.name == "CRITICAL" and "OGNL" in el["caption"].title
    assert el["cond"].severity.name == "HIGH" and "SpEL" in el["cond"].title  # sandboxed
    assert all(f.location.method == "GET" for f in el.values())


async def test_an_el_proof_is_not_also_reported_as_ssti(scan) -> None:
    """The combined detector gives one finding per proof; ``/greet`` stays a Jinja2 ``ssti``."""
    result = await scan("insecure", **_ACTIVE)
    ssti = {f.location.param for f in result.findings if f.check_id == "injection.ssti"}
    assert not ssti & {"filter", "caption", "cond"}
    assert "name" in ssti


async def test_crlf_injection_found_on_the_insecure_set_lang_endpoint(scan) -> None:
    """The ``/set-lang`` endpoint writes ``lang`` into a header unfiltered — a HIGH CRLF hit."""
    result = await scan("insecure", **_ACTIVE)
    crlf = [f for f in result.findings if f.check_id == "injection.crlf"]
    assert crlf, "expected a CRLF-injection finding"
    assert any(f.location.param == "lang" for f in crlf)
    assert crlf[0].severity.name == "HIGH"


async def test_host_header_injection_found_on_the_insecure_reset_page(scan) -> None:
    """The ``/reset`` link is built from the request Host header — a host-header finding."""
    result = await scan("insecure", **_ACTIVE)
    hh = [f for f in result.findings if f.check_id == "injection.host-header"]
    assert hh, "expected a host-header-injection finding"
    assert any(
        "Forwarded-Host" in (f.location.param or "") or f.location.param == "Host" for f in hh
    )


async def test_trace_and_dangerous_methods_reported_on_the_insecure_profile(scan) -> None:
    """``/resource`` advertises TRACE + PUT + DELETE and echoes TRACE — a methods finding."""
    result = await scan("insecure", **_ACTIVE)
    methods = [f for f in result.findings if f.check_id == "http.methods.unsafe"]
    assert methods, "expected an unsafe-HTTP-methods finding"
    assert any("/resource" in (f.location.url or "") for f in methods)


async def test_ldap_xpath_ssi_detectors_fire_on_the_insecure_profile(scan) -> None:
    """An active scan of the insecure profile finds the three spec-014 injection sinks."""
    result = await scan("insecure", **_ACTIVE)
    reported = {f.check_id for f in result.findings}
    assert "injection.ldap" in reported
    assert "injection.xpath" in reported
    assert "injection.ssi" in reported


async def test_the_login_form_is_never_fuzzed(scan) -> None:
    """The login form is never submitted with a payload, even during an active scan."""
    await scan("insecure", **_ACTIVE)
    log = _log(scan)
    # The crawler may GET /login (it is the redirect target of /account), but the login
    # form is never submitted with a payload.
    assert not any(entry.startswith("POST /login") for entry in log)
    assert not any(entry.startswith("GET /login?") and entry != "GET /login?" for entry in log)


async def test_opt_in_passes_do_not_run_without_their_switch(scan) -> None:
    """A default Active scan runs no XXE, upload, stored-XSS, CSRF-confirmation or POST pass."""
    result = await scan("insecure", **_ACTIVE)
    checks = {f.check_id for f in result.findings}
    assert not checks & {"injection.xxe", "upload.unrestricted", "injection.xss.stored"}
    assert "csrf.form.token-not-enforced" not in checks
    log = _log(scan)
    assert not any(entry.startswith("POST /upload") for entry in log)
    # the per-entry pages are only fetched by the stored-XSS Phase B re-crawl
    assert not any(entry.startswith("GET /guestbook/e/") for entry in log)
    app = scan.holder["app"]
    assert not [e for e in app.state.csrf_log if "wvcsrf" in e[3]]  # type: ignore[attr-defined]
    assert not [  # type: ignore[attr-defined]
        e for e in app.state.post_log if any(str(v).startswith("wvcrawl") for v in e[2].values())
    ]
    assert not any(w.startswith(("POST crawl:", "CSRF confirmation:")) for w in result.warnings)
    # the passive finding for the tokenless form is untouched (spec 017 RF-10)
    assert any(
        f.check_id == "csrf.form.no-token" and f.location.url.endswith("/newsletter")
        for f in result.findings
    )


# ---------------------------------------------------------------------------
# Authenticated scanning, CSRF detection, form-driven crawling (spec 007) — passive
# ---------------------------------------------------------------------------


async def test_authenticated_scan_reaches_the_account_area(scan) -> None:
    """With a session cookie the crawl reaches the behind-login account pages."""
    result = await scan("insecure", cookies=["session=abc123"])
    log = _log(scan)
    assert "GET /account?" in log
    assert "GET /account/settings?" in log
    assert result.metadata.authenticated is True


async def test_anonymous_scan_stops_at_the_login_redirect(scan) -> None:
    """An anonymous scan cannot get past the login redirect into the account area."""
    await scan("insecure")
    assert not any("/account/settings" in e for e in _log(scan))


async def test_crawler_submits_the_get_search_form(scan) -> None:
    """The crawler submits the safe GET search form."""
    await scan("insecure")
    assert any(e.startswith("GET /search?q=") for e in _log(scan))


async def test_crawler_never_submits_post_forms_or_logout(scan) -> None:
    """The crawler never POSTs a form or follows a logout link, even authenticated."""
    await scan("insecure", cookies=["session=abc123"])  # authenticated, passive
    log = _log(scan)
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


# ---------------------------------------------------------------------------
# Determinism — passive scans, then the one scan that turns everything on
# ---------------------------------------------------------------------------


async def test_passive_scans_are_deterministic(scan) -> None:
    """Probe, OSV-online and authenticated scans each yield the same findings twice."""
    for options in ({"probe": True}, {"osv_online": True}, {"cookies": ["session=abc123"]}):
        first = await scan("insecure", **options)
        second = await scan.fresh("insecure", **options)
        assert first.findings, options
        _assert_same_findings(first, second)
        assert [f.fingerprint for f in first.findings] == [f.fingerprint for f in second.findings]


async def test_full_scan_is_deterministic(scan) -> None:
    """Two scans with every switch on report the same findings (every spec's determinism)."""
    first = await scan("insecure", **_full("insecure"))
    second = await scan.fresh("insecure", **_full("insecure"))
    assert first.findings
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
# The scan with every switch on (specs 008, 012, 013, 014, 017, 018)
# ---------------------------------------------------------------------------


def _stored(result: ScanResult) -> list[Finding]:
    """
    Args:
        result (ScanResult): A finished scan result.

    Returns:
        list[Finding]: Its ``injection.xss.stored`` findings.
    """
    return [f for f in result.findings if f.check_id == "injection.xss.stored"]


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


def _csrf_writes(scan) -> list[tuple[str, bool, str, str]]:
    """
    Args:
        scan: The ``scan`` fixture — ``scan.holder`` holds the app the scan ran against.

    Returns:
        list[tuple[str, bool, str, str]]: The ``csrf_log`` entries the CSRF pass caused (the
            ones carrying its ``wvcsrf`` sentinel), as ``(route, accepted, Origin, value)``.
    """
    app = scan.holder["app"]
    return [entry for entry in app.state.csrf_log if "wvcsrf" in entry[3]]  # type: ignore[attr-defined]


def _crawl_posts(scan) -> list[tuple[str, str, dict[str, object]]]:
    """
    Args:
        scan: The ``scan`` fixture — ``scan.holder`` holds the app the scan ran against.

    Returns:
        list[tuple[str, str, dict[str, object]]]: The ``post_log`` entries the crawler's POST
            phase caused: the ones carrying its ``wvcrawl`` marker, plus the JSON notes post
            (the importer's synthesised body has no marker, and nothing else posts JSON).
    """
    app = scan.holder["app"]
    return [
        entry
        for entry in app.state.post_log  # type: ignore[attr-defined]
        if entry[1] == "application/json"
        or any(str(value).startswith("wvcrawl") for value in entry[2].values())
    ]


async def test_the_full_scan_runs_clean_and_within_budget(scan) -> None:
    """Every switch on at once: no pass errors, and no pass starved by the shared budgets."""
    result = await scan("insecure", **_full("insecure"))
    assert result.errors == ()
    assert result.metadata.authenticated is True
    # a pass that hit one of its caps says "stopped at the N-request budget / N-page cap"
    assert not any("stopped at" in warning for warning in result.warnings), result.warnings


async def test_stored_xss_found_on_the_insecure_guestbook(scan) -> None:
    """The stored-XSS pass finds the guestbook sink: POST ``body``, rendered on a per-entry page."""
    result = await scan("insecure", **_full("insecure"))
    gb = next((f for f in _stored(result) if f.location.url.endswith("/guestbook")), None)
    assert gb is not None
    assert (gb.location.method, gb.location.param) == ("POST", "body")
    # /guestbook only lists links; the raw marker renders on /guestbook/e/<id>, which the
    # first crawl never saw — proving the one-hop re-crawl reached it.
    rendered_on = {e.label: e.content for e in gb.evidence}["Rendered on"]
    assert re.search(r"/guestbook/e/\d+", rendered_on)


async def test_authenticated_stored_xss_reaches_the_account_area(scan) -> None:
    """Authenticated stored XSS reaches the behind-login ``/profile`` sink."""
    result = await scan("insecure", **_full("insecure"))
    params = {(f.location.method, f.location.param) for f in _stored(result)}
    assert ("POST", "nickname") in params


async def test_xxe_found_with_the_opt_in(scan) -> None:
    """``/api/xml`` resolves entities, and the XXE step (``--xxe``) proves it."""
    result = await scan("insecure", **_full("insecure"))
    xxe = [f for f in result.findings if f.check_id == "injection.xxe"]
    assert xxe and xxe[0].severity.name == "HIGH"


async def test_file_upload_pass_finds_the_unrestricted_endpoint_with_the_opt_in(scan) -> None:
    """``--file-upload`` uploads markers through ``/upload`` and proves several outcomes."""
    result = await scan("insecure", **_full("insecure"))
    uploads = [f for f in result.findings if f.check_id == "upload.unrestricted"]
    assert uploads
    assert {f.severity.name for f in uploads} & {"CRITICAL", "HIGH"}
    assert {f.location.method for f in uploads} & {"PUT", "POST"}


async def test_openapi_import_reaches_an_unlinked_endpoint_and_fuzzes_it(scan) -> None:
    """``--openapi`` seeds ``/api/find`` (linked from nowhere) and the XSS detector hits it."""
    result = await scan("insecure", **_full("insecure"))
    xss = [
        f
        for f in result.findings
        if f.check_id == "injection.xss.reflected" and "/api/find" in (f.location.url or "")
    ]
    assert xss and xss[0].location.param == "q"
    assert any(entry.startswith("GET /api/find?") for entry in _log(scan))


async def test_the_full_scan_logs_in_once_and_reaches_the_account_area(scan) -> None:
    """One ``POST /signin`` for the whole scan, and the logged-in pages are crawled."""
    result = await scan("insecure", **_full("insecure"))
    app = scan.holder["app"]
    assert app.state.login_log == ["ok"]
    assert result.metadata.authenticated is True
    assert result.metadata.login == LoginSummary(relogins=0, session_lost=False, confirmed=True)
    assert any(entry.startswith("GET /account/settings") for entry in _log(scan))
    assert not any("login requires" in w for w in result.warnings)


async def test_a_session_that_expires_is_re_authenticated_and_the_scan_goes_on(scan) -> None:
    """The session dies after a few requests: re-login(s), the crawl continues, no loss."""
    result = await scan("hardened", active=True, time_based=False, login=True, session_ttl=2)
    app = scan.holder["app"]
    login = result.metadata.login
    assert login is not None and login.relogins >= 1 and not login.session_lost
    assert app.state.login_log == ["ok"] * (1 + login.relogins)  # one POST per login, no more
    assert app.state.expired  # the sessions really did expire under the scan
    assert not any("lost" in w for w in result.warnings)


async def test_a_passive_scan_with_a_login_sends_no_login_request(scan) -> None:
    """Passive never logs in: a warning, and the target never sees ``/signin``."""
    result = await scan("insecure", login=True)
    assert not any("/signin" in entry for entry in _log(scan))
    assert scan.holder["app"].state.login_log == []
    assert any("login requires --mode active" in w for w in result.warnings)
    assert result.metadata.login is None and result.metadata.authenticated is False


_SESSION_CHECKS = {
    "session.id.weak",
    "session.fixation",
    "session.logout.not-invalidated",
}


async def test_session_checks_find_the_three_weaknesses_of_the_insecure_app(scan) -> None:
    """Weak ids, a fixed session and a logout that does not end it, each naming the cookie only."""
    result = await scan("insecure", **_full("insecure"))
    found = {f.check_id: f for f in result.findings if f.check_id in _SESSION_CHECKS}
    assert set(found) == _SESSION_CHECKS
    assert {f.location.cookie for f in found.values()} == {"session"}
    assert found["session.id.weak"].confidence.name == "HIGH"  # the sampled visits repeated an id

    app = scan.holder["app"]
    values = {*app.state.sessions, *app.state.expired, "abc123"}
    for finding in found.values():
        text = finding.model_dump_json()
        assert not any(value in text for value in values), finding.check_id


async def test_the_logout_test_runs_last_and_no_login_follows_it(scan) -> None:
    """Right after the logout: the redirect it follows, the anonymous replay, and no re-login."""
    await scan("insecure", **_full("insecure"))
    log = _log(scan)
    logout = max(i for i, entry in enumerate(log) if entry.startswith("GET /logout?"))
    assert log[logout + 1 : logout + 3] == ["GET /?", "GET /account?"]  # the redirect, the replay
    # the session was closed on purpose: nothing logs in again (the checks that still run, such as
    # the CORS probe, make their own unauthenticated requests)
    assert not any("/signin" in entry for entry in log[logout:])
    assert scan.holder["app"].state.logout_log == [True]


async def test_the_hardened_app_passes_every_session_check(scan) -> None:
    """Long random ids, a new id at login and a server-side logout: nothing to report."""
    result = await scan("hardened", **_full("hardened"))
    assert not [f for f in result.findings if f.check_id in _SESSION_CHECKS]
    app = scan.holder["app"]
    assert app.state.logout_log == [True] and app.state.expired  # the logout really ended it
    assert not any("session" in w and "skipped" in w for w in result.warnings)


async def test_secrets_never_appear_in_any_report(scan) -> None:
    """The login password, the session values and a bearer token reach no report format."""
    result = await scan("insecure", **_full("insecure"))
    issued = set(scan.holder["app"].state.sessions) | scan.holder["app"].state.expired
    assert issued  # the scan really logged in, so there is a session value to look for
    secrets = {SIGNIN_PASSWORD, "wv-secret-123", *issued}
    for fmt in ("json", "sarif", "html", "md"):
        rendered = get_reporter(fmt).render(result)
        for secret in secrets:
            assert secret not in rendered, (fmt, secret)  # never leaves, even via the TRACE echo
    assert all(secret not in warning for warning in result.warnings for secret in secrets)


async def test_csrf_confirmation_flags_the_unenforced_forms_only(scan) -> None:
    """The no-token and ignored-token forms are confirmed; the enforced ones are not."""
    result = await scan("insecure", **_full("insecure"))
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
    writes = _csrf_writes(scan)
    assert any(origin == "https://webvigil.invalid" for _, _, origin, _ in writes)
    refused = {route for route, accepted, origin, _ in writes if not accepted}
    assert "prefs" in refused and "transfer" in refused


async def test_csrf_confirmation_stops_at_the_first_confirming_replay(scan) -> None:
    """A confirmed form is written to twice at most: the control and one replay."""
    await scan("insecure", **_full("insecure"))
    writes = _csrf_writes(scan)
    assert sum(1 for route, *_ in writes if route == "settings") == 2
    assert sum(1 for route, *_ in writes if route == "newsletter") == 2


async def test_post_crawl_reaches_what_only_a_post_leads_to(scan) -> None:
    """The answers become pages and their links are followed; bodies arrive as declared."""
    result = await scan("insecure", **_full("insecure"))
    posts = _crawl_posts(scan)
    assert {"ticket", "callback", "feedback", "notes"} <= {entry[0] for entry in posts}
    # the answers' links were followed: the status page is linked only from the ticket answer
    log = _log(scan)
    assert any(line.startswith("GET /support/status") for line in log)
    # the multipart and JSON bodies arrived as such
    kinds = {entry[0]: entry[1] for entry in posts}
    assert kinds["callback"].startswith("multipart/form-data")
    assert kinds["notes"] == "application/json"
    # defaults and the marker only: no payload
    for route, _, fields in posts:
        if route in {
            "notes",
            "spa-note",
        }:  # JSON bodies: a synthesised or recorded shape, no payload
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


# ---------------------------------------------------------------------------
# The hardened twin of the scan with every switch on: nothing is reported
# ---------------------------------------------------------------------------


async def test_hardened_profile_with_every_switch_reports_nothing(scan) -> None:
    """Every hardened route validates, escapes or enforces: no finding of any spec, no error.

    This is the single hardened check for the injection, SSRF, RCE, expression-language,
    request-envelope, upload, stored-XSS, CSRF-confirmation and POST-crawl specs; the passes
    still ran (below), so "nothing" means "tested and found safe".
    """
    result = await scan("hardened", **_full("hardened"))
    assert result.findings == ()
    assert result.errors == ()
    # the CSRF confirmation ran and found every token enforced: replays refused, controls accepted
    assert any(w.startswith("CSRF confirmation:") and "0 confirmed" in w for w in result.warnings)
    writes = _csrf_writes(scan)
    replays = [
        accepted for _, accepted, origin, _ in writes if origin == "https://webvigil.invalid"
    ]
    assert replays and not any(replays)
    assert any(
        accepted for _, accepted, origin, _ in writes if origin != "https://webvigil.invalid"
    )
    # the POST crawl ran and the answers were read
    assert {"ticket", "callback", "feedback"} <= {entry[0] for entry in _crawl_posts(scan)}


# ---------------------------------------------------------------------------
# HAR import (spec 021)
# ---------------------------------------------------------------------------


async def test_har_import_reaches_unlinked_routes_and_fuzzes_the_get_one(scan) -> None:
    """The HAR seeds ``/spa/items`` with its recorded query and the XSS detector hits it."""
    result = await scan("insecure", **_full("insecure"))
    assert "GET /spa/items?name=widget" in _log(scan)
    xss = [
        f
        for f in result.findings
        if f.check_id == "injection.xss.reflected" and "/spa/items" in (f.location.url or "")
    ]
    assert xss and xss[0].location.param in {"name", "tab"}


async def test_har_import_summary_and_the_entries_it_must_leave_alone(scan) -> None:
    """The summary says what was read; the foreign host, asset, DELETE and login are never sent."""
    result = await scan("insecure", **_full("insecure"))
    assert (
        "HAR import: 7 entries read, 3 operations seeded (2 GET, 1 POST); ignored: "
        "1 out of scope, 1 static, 1 other method, 1 unsafe"
    ) in result.warnings
    log = _log(scan)
    assert not any("only-on-cdn" in line or "session/login" in line for line in log)
    assert not any(line.startswith("DELETE") or "app.js" in line for line in log)
    assert not any("looks authenticated" in w for w in result.warnings)  # the scan has a login


async def test_har_post_operation_is_posted_once_with_the_recorded_shape_only(scan) -> None:
    """In the Active scan with ``--submit-post-forms`` the JSON POST goes out once, as a shape."""
    await scan("insecure", **_full("insecure"))
    notes = [e for e in scan.holder["app"].state.post_log if e[0] == "spa-note"]  # type: ignore[attr-defined]
    assert notes == [("spa-note", "application/json", {"text": "wv"})]


async def test_nothing_the_har_held_in_secret_reaches_any_report(scan) -> None:
    """RNF-05: a cookie, a bearer, a ``?token=`` and a JSON value of the file are in no format."""
    result = await scan("insecure", **_full("insecure"))
    for fmt in ("json", "sarif", "html", "md"):
        rendered = get_reporter(fmt).render(result)
        for secret in _HAR_SECRETS:
            assert secret not in rendered, (fmt, secret)
    assert all(secret not in w for w in result.warnings for secret in _HAR_SECRETS)
    assert not any(secret in line for line in _log(scan) for secret in _HAR_SECRETS)


async def test_a_passive_scan_with_a_har_seeds_the_gets_sends_no_post_and_warns_about_the_session(
    scan,
) -> None:
    """Passive: the GET seed is fetched, the POST route is never touched, and the recording that
    looks authenticated draws the one warning (this scan has no credentials)."""
    result = await scan("insecure", har=_HAR["path"])
    log = _log(scan)
    assert "GET /spa/items?name=widget" in log
    assert not any(line.startswith("POST /spa") for line in log)
    assert scan.holder["app"].state.post_log == []  # type: ignore[attr-defined]
    looks = [w for w in result.warnings if "looks authenticated" in w]
    assert len(looks) == 1 and "--login-url" in looks[0]
    assert not any(secret in looks[0] for secret in _HAR_SECRETS)
