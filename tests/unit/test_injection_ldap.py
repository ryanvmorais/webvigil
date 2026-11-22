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
import pytest

from webvigil.checks.injection import payloads
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


def _widens(v: str) -> bool:
    """
    Args:
        v (str): A sent value.

    Returns:
        bool: ``True`` for the always-true probes of ``payloads.LDAP_BOOLEAN``.
    """
    return v == "*" or "uid=*" in v


async def test_a_widen_that_does_not_reproduce_is_not_a_hit() -> None:
    """The confirmation repeats the pair: a widen seen once (a flaky page) is not a hit."""
    seen: list[str] = []

    def render(v: str) -> Response:
        seen.append(v)
        return _resp(_WIDE_BODY if _widens(v) and seen.count(v) == 1 else _BASE_BODY)

    assert await ldap.detect(_POINT, _baseline(), _ctx(render)) == []
    assert seen.count("*)(uid=*))(|(uid=*") == 2  # the first pair widened and was repeated


async def test_a_widen_seen_only_on_the_repeat_is_not_a_hit() -> None:
    """The first answer of a pair is judged too: a widen that only the repeat shows is not one."""
    seen: list[str] = []

    def render(v: str) -> Response:
        seen.append(v)
        return _resp(_WIDE_BODY if _widens(v) and seen.count(v) > 1 else _BASE_BODY)

    assert await ldap.detect(_POINT, _baseline(), _ctx(render)) == []
    assert seen.count("*)(uid=*))(|(uid=*") == 1  # not widened, so never repeated


# The error stage sends one request per probe; then the first boolean pair (TRUE, FALSE) and
# its confirmation (TRUE, FALSE). Each case fails one of those four requests and nothing else.
_ERRORS = len(payloads.LDAP_ERROR)


@pytest.mark.parametrize(
    ("failed", "sent"),
    [
        (_ERRORS, _ERRORS + 2),
        (_ERRORS + 1, _ERRORS + 2),
        (_ERRORS + 2, _ERRORS + 4),
        (_ERRORS + 3, _ERRORS + 4),
    ],
    ids=["true", "false", "confirm-true", "confirm-false"],
)
async def test_one_failed_boolean_request_ends_the_detector(failed: int, sent: int) -> None:
    """A request that fails (``None``) in either pair stops the routine with no hit."""
    calls: list[str] = []

    def render(v: str) -> Response | None:
        calls.append(v)
        if len(calls) - 1 == failed:
            return None
        return _resp(_WIDE_BODY if _widens(v) else _BASE_BODY)

    assert await ldap.detect(_POINT, _baseline(), _ctx(render)) == []
    assert len(calls) == sent


def test_is_ldaplike_matches_directory_parameter_names() -> None:
    """``user`` / ``uid`` / ``cn`` are front-loaded; ``colour`` is not."""
    assert is_ldaplike(_POINT) is True
    other = InjectionPoint("GET", "https://example.com/x", "colour", "red", (("colour", "red"),))
    assert is_ldaplike(other) is False
