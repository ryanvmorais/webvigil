"""
LDAP-injection detector — spec 014 RF-08, RF-17.

Pure detector unit: ``_ctx`` wraps a ``render`` callable keyed on the sent value.
The error probe runs first (a filter metacharacter appended to the original
value); the boolean probe sends an always-true filter that widens the result set
and an always-false one that does not.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

from webvigil.checks.injection.detect import DetectCtx, ldap, normalize_body
from webvigil.checks.injection.models import Baseline, InjectionPoint
from webvigil.checks.injection.points import is_ldaplike
from webvigil.core.findings import Confidence, Severity
from webvigil.http.client import Response

_POINT = InjectionPoint("GET", "https://example.com/dir", "user", "jdoe", (("user", "jdoe"),))
_BASE_BODY = "1 result: uid=jdoe\n" * 3
_WIDE_BODY = "".join(f"result: uid=user{i}\n" for i in range(200))


def _resp(text: str) -> Response:
    return Response(
        url="https://example.com/dir",
        requested_url="https://example.com/dir",
        status_code=200,
        headers=httpx.Headers({"content-type": "text/plain"}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
    )


def _baseline(body: str = _BASE_BODY) -> Baseline:
    return Baseline(200, body, normalize_body(body), len(body), 1.0)


def _ctx(render: Callable[[str], Response | None]) -> DetectCtx:
    async def send(
        point: InjectionPoint,
        value: str,
        *,
        time_based: bool = False,
        content_type: str | None = None,
    ) -> Response | None:
        return render(value)

    return DetectCtx(send=send, delay_s=5, host="example.com")


async def test_filter_error_signature_is_a_high_hit() -> None:
    """An LDAP parser error the baseline never had is a HIGH / HIGH hit."""
    hits = await ldap.detect(
        _POINT,
        _baseline(),
        _ctx(
            lambda v: _resp(
                "javax.naming.directory.InvalidSearchFilterException: Bad search filter"
            )
        ),
    )
    assert len(hits) == 1
    assert hits[0].kind == "ldap"
    assert hits[0].check_id == "injection.ldap"
    assert hits[0].severity is Severity.HIGH
    assert hits[0].confidence is Confidence.HIGH


async def test_result_set_widen_that_reproduces_is_a_medium_hit() -> None:
    """An always-true filter that widens the result set, confirmed, is MEDIUM / MEDIUM."""

    def render(v: str) -> Response:
        if v == "*" or "uid=*" in v:
            return _resp(_WIDE_BODY)
        return _resp(_BASE_BODY)

    hits = await ldap.detect(_POINT, _baseline(), _ctx(render))
    assert len(hits) == 1
    assert hits[0].severity is Severity.MEDIUM
    assert hits[0].confidence is Confidence.MEDIUM


async def test_one_sided_change_is_not_a_hit() -> None:
    """A widened TRUE response with a FALSE response that also diverges is not a hit."""

    def render(v: str) -> Response:
        if v == "*" or "uid=*" in v:
            return _resp(_WIDE_BODY)
        if v.startswith("jdoe") and v != "jdoe":  # the FALSE probe also moves
            return _resp("totally different page " * 40)
        return _resp(_BASE_BODY)

    assert await ldap.detect(_POINT, _baseline(), _ctx(render)) == []


async def test_error_signature_already_in_the_baseline_is_suppressed() -> None:
    """A parser error already present in the baseline body is not a new finding."""
    err = "javax.naming.directory something Bad search filter"
    hits = await ldap.detect(_POINT, _baseline(err), _ctx(lambda v: _resp(err)))
    assert hits == []


async def test_send_returning_none_stops_the_detector() -> None:
    """When the budget denies a send the detector returns no hits."""
    assert await ldap.detect(_POINT, _baseline(), _ctx(lambda v: None)) == []


def test_is_ldaplike_matches_directory_parameter_names() -> None:
    """``user`` / ``uid`` / ``cn`` are front-loaded; ``colour`` is not."""
    assert is_ldaplike(_POINT) is True
    other = InjectionPoint("GET", "https://example.com/x", "colour", "red", (("colour", "red"),))
    assert is_ldaplike(other) is False
