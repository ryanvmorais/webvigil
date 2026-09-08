"""
OsvProvider: normalisation, severity mapping, name mapping, and the batched I/O — spec 010.

Every test uses ``httpx.MockTransport``; nothing here touches the real network (RF-16).
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from webvigil.checks.deps import _data
from webvigil.checks.deps.osv import (
    OsvLookupError,
    OsvProvider,
    _band,
    _cvss3_base,
    _first_safe,
    _npm_name,
    _severity,
    _to_advisory,
)
from webvigil.core.context import Detection
from webvigil.core.findings import Severity
from webvigil.core.technology import DetectionMethod

# --- fixtures / helpers ---------------------------------------------------------------

_GHSA_RECORD: dict[str, Any] = {
    "id": "GHSA-gxr4-xjj5-5px2",
    "aliases": ["CVE-2020-11022"],
    "summary": "Cross-site scripting in jQuery",
    "details": "Passing HTML from untrusted sources to jQuery may execute untrusted code.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "jquery"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "1.2.0"}, {"fixed": "3.5.0"}]}
            ],
        }
    ],
    "references": [{"type": "WEB", "url": "https://blog.jquery.com/2020/04/10/jquery-3-5-0/"}],
    "database_specific": {"severity": "MODERATE", "cwe_ids": ["CWE-79"]},
}

_CVE_RECORD: dict[str, Any] = {
    "id": "CVE-2019-11358",
    "details": "jQuery before 3.4.0 mishandles __proto__. A later sentence adds detail.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "jquery"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.4.0"}]}],
        }
    ],
    "references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-11358"}],
    "database_specific": {},
}


def _det(name: str, version: str | None) -> Detection:
    return Detection(
        name=name,
        version=version,
        method=DetectionMethod.FILENAME,
        source_url="https://demo.test/jquery.js",
        marker="jquery.js",
    )


class _Transport:
    """A MockTransport that records call paths and the querybatch body it received."""

    def __init__(
        self,
        *,
        batch: dict[str, Any],
        queries: dict[str, dict[str, Any]] | None = None,
        batch_status: int = 200,
        query_status: int = 200,
    ) -> None:
        self.calls: list[str] = []
        self.sent_queries: list[dict[str, Any]] = []
        self._batch = batch
        self._queries = queries or {}
        self._batch_status = batch_status
        self._query_status = query_status

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request.url.path)
        body = json.loads(request.content) if request.content else {}
        if request.url.path == "/v1/querybatch":
            self.sent_queries = body.get("queries", [])
            return httpx.Response(self._batch_status, json=self._batch)
        if request.url.path == "/v1/query":
            name = body["package"]["name"]
            return httpx.Response(self._query_status, json=self._queries.get(name, {"vulns": []}))
        return httpx.Response(404, json={})


def _provider(transport: httpx.MockTransport) -> OsvProvider:
    return OsvProvider("http://osv.test", 5.0, user_agent="WebVigil/test", transport=transport)


# --- name mapping (RF-05) ------------------------------------------------------------


def test_npm_name_maps_known_aliases_and_passes_through_the_rest() -> None:
    assert _npm_name("angularjs") == "angular"
    assert _npm_name("jquery.ui") == "jquery-ui"
    assert _npm_name("jquery") == "jquery"
    assert _npm_name("a-library-we-never-heard-of") == "a-library-we-never-heard-of"


def test_every_vendored_component_resolves_to_a_non_empty_npm_name() -> None:
    for name in _data.load_raw_db().get("components", {}):
        assert _npm_name(name).strip(), name


# --- CVSS base score (RF-07, ADR-5) -------------------------------------------------


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", 3.7),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ],
)
def test_cvss3_base_matches_published_scores(vector: str, score: float) -> None:
    assert _cvss3_base(vector) == score


def test_cvss3_base_rejects_non_v3_vectors() -> None:
    assert _cvss3_base("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None
    assert _cvss3_base("CVSS:2.0/AV:N/AC:L") is None
    assert _cvss3_base("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None  # bad metric


def test_band_edges() -> None:
    assert _band(0.0) is None
    assert _band(3.9) is Severity.LOW
    assert _band(4.0) is Severity.MEDIUM
    assert _band(7.0) is Severity.HIGH
    assert _band(9.0) is Severity.CRITICAL


# --- severity selection (RF-07) ----------------------------------------------------


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("LOW", Severity.LOW),
        ("MODERATE", Severity.MEDIUM),
        ("MEDIUM", Severity.MEDIUM),
        ("HIGH", Severity.HIGH),
        ("CRITICAL", Severity.CRITICAL),
    ],
)
def test_ghsa_severity_label_wins(label: str, expected: Severity) -> None:
    severity, from_upstream = _severity({"database_specific": {"severity": label}})
    assert severity is expected
    assert from_upstream is True


def test_cvss_vector_used_when_no_ghsa_label() -> None:
    record = {
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    }
    severity, from_upstream = _severity(record)
    assert severity is Severity.CRITICAL
    assert from_upstream is True


def test_missing_severity_falls_back_to_medium() -> None:
    assert _severity({}) == (Severity.MEDIUM, False)


def test_cvss_v2_vector_is_not_parsed() -> None:
    record = {"severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}]}
    assert _severity(record) == (Severity.MEDIUM, False)


# --- first safe version (RF-06) ---------------------------------------------------


def test_first_safe_picks_the_lowest_fixed_above_the_detected_version() -> None:
    record = {
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "jquery"},
                "ranges": [
                    {"events": [{"introduced": "0"}, {"fixed": "1.9.0"}]},
                    {"events": [{"introduced": "2.0.0"}, {"fixed": "3.5.0"}]},
                ],
            }
        ]
    }
    assert _first_safe(record, "jquery", "3.0.0") == "3.5.0"
    assert _first_safe(record, "jquery", "1.5.0") == "1.9.0"


def test_first_safe_is_none_with_only_last_affected() -> None:
    record = {
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "jquery"},
                "ranges": [{"events": [{"introduced": "0"}, {"last_affected": "3.4.1"}]}],
            }
        ]
    }
    assert _first_safe(record, "jquery", "3.0.0") is None


def test_first_safe_ignores_a_non_matching_package() -> None:
    record = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "jquery"},
                "ranges": [{"events": [{"fixed": "9.9.9"}]}],
            }
        ]
    }
    assert _first_safe(record, "jquery", "3.0.0") is None


# --- record -> Advisory (RF-06) --------------------------------------------------


def test_to_advisory_from_a_ghsa_record() -> None:
    advisory = _to_advisory(_GHSA_RECORD, npm_name="jquery", detected_version="3.4.1")
    assert advisory is not None
    assert advisory.identifiers == ("GHSA-gxr4-xjj5-5px2", "CVE-2020-11022")
    assert advisory.summary == "Cross-site scripting in jQuery"
    assert advisory.severity is Severity.MEDIUM  # MODERATE
    assert advisory.severity_from_upstream is True
    assert advisory.first_safe_version == "3.5.0"
    assert advisory.cwe == (79,)
    assert "https://osv.dev/vulnerability/GHSA-gxr4-xjj5-5px2" in advisory.info_urls
    assert "https://blog.jquery.com/2020/04/10/jquery-3-5-0/" in advisory.info_urls


def test_to_advisory_from_a_cve_only_record_uses_details_and_cvss() -> None:
    advisory = _to_advisory(_CVE_RECORD, npm_name="jquery", detected_version="3.3.0")
    assert advisory is not None
    assert advisory.identifiers == ("CVE-2019-11358",)
    assert advisory.summary == "jQuery before 3.4.0 mishandles __proto__."
    assert advisory.severity is Severity.MEDIUM  # from the CVSS vector
    assert advisory.severity_from_upstream is True
    assert advisory.first_safe_version == "3.4.0"
    assert advisory.cwe == ()


def test_to_advisory_returns_none_for_a_record_without_an_id() -> None:
    assert _to_advisory({"summary": "x"}, npm_name="jquery", detected_version="1.0.0") is None


# --- OsvProvider.lookup (RF-04, RF-09, RF-11) -----------------------------------


async def test_all_clean_querybatch_makes_no_follow_up_query() -> None:
    mock = _Transport(batch={"results": [{}, {}]})
    result = await _provider(mock.transport).lookup(
        [_det("jquery", "3.6.0"), _det("lodash", "4.17.21")]
    )
    assert result.advisories == {}
    assert mock.calls == ["/v1/querybatch"]


async def test_one_hit_triggers_exactly_one_query() -> None:
    mock = _Transport(
        batch={"results": [{"vulns": [{"id": "GHSA-gxr4-xjj5-5px2"}]}, {}]},
        queries={"jquery": {"vulns": [_GHSA_RECORD]}},
    )
    result = await _provider(mock.transport).lookup(
        [_det("jquery", "3.4.1"), _det("lodash", "4.17.21")]
    )
    assert mock.calls == ["/v1/querybatch", "/v1/query"]
    assert set(result.advisories) == {("jquery", "3.4.1")}
    assert result.advisories[("jquery", "3.4.1")][0].identifiers[0] == "GHSA-gxr4-xjj5-5px2"


async def test_repeated_detection_is_sent_and_queried_once() -> None:
    mock = _Transport(
        batch={"results": [{"vulns": [{"id": "GHSA-gxr4-xjj5-5px2"}]}]},
        queries={"jquery": {"vulns": [_GHSA_RECORD]}},
    )
    await _provider(mock.transport).lookup([_det("jquery", "3.4.1"), _det("jquery", "3.4.1")])
    assert len(mock.sent_queries) == 1
    assert mock.calls == ["/v1/querybatch", "/v1/query"]


async def test_version_undetermined_detections_are_skipped() -> None:
    mock = _Transport(batch={"results": []})
    result = await _provider(mock.transport).lookup([_det("jquery", None)])
    assert result.advisories == {}
    assert mock.calls == []


async def test_querybatch_error_status_raises() -> None:
    mock = _Transport(batch={}, batch_status=500)
    with pytest.raises(OsvLookupError):
        await _provider(mock.transport).lookup([_det("jquery", "3.4.1")])


async def test_non_json_body_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>not json</html>")

    with pytest.raises(OsvLookupError):
        await _provider(httpx.MockTransport(handler)).lookup([_det("jquery", "3.4.1")])


async def test_transport_error_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with pytest.raises(OsvLookupError):
        await _provider(httpx.MockTransport(handler)).lookup([_det("jquery", "3.4.1")])


async def test_partial_query_failure_keeps_the_rest_and_warns() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(
                200,
                json={"results": [{"vulns": [{"id": "GHSA-j"}]}, {"vulns": [{"id": "GHSA-l"}]}]},
            )
        body = json.loads(request.content)
        if body["package"]["name"] == "jquery":
            return httpx.Response(200, json={"vulns": [_GHSA_RECORD]})
        return httpx.Response(503, json={})

    result = await _provider(httpx.MockTransport(handler)).lookup(
        [_det("jquery", "3.4.1"), _det("lodash", "4.17.20")]
    )
    assert ("jquery", "3.4.1") in result.advisories
    assert ("lodash", "4.17.20") not in result.advisories
    assert result.warnings and "lodash" in result.warnings[0]
