"""
What the checks do with a page or a response costs time and memory proportional to it.

The text these checks read comes from the scanned site, so a pattern whose matching time grows
faster than the text, or a check that keeps one finding per item a page lists, would let a hostile
site stall a scan or fill its memory. Nothing is mocked: each test hands a check, a validator or a
detector a real string and reads the verdict, the findings or the clock. The time limit is far
above what the bounded code needs and far below what the unbounded code needed on the same input,
so a slow CI runner cannot fail it and a regression cannot pass it.
"""

from __future__ import annotations

import json
import re
import time

import httpx
import pytest

from tests.support import HandlerTransport, make_context, make_page
from webvigil.checks.base import PER_PAGE_FINDINGS_CAP
from webvigil.checks.content.checks import MixedContentCheck, SriMissingCheck
from webvigil.checks.cookies.flags import CookieFlagsCheck
from webvigil.checks.disclosure import redaction
from webvigil.checks.disclosure.catalogue import _SCAN_MAX, Validator, load_catalogue
from webvigil.checks.disclosure.leakage import SessionIdInUrlCheck
from webvigil.checks.injection.detect.redirect import _honoured
from webvigil.checks.registry import all_checks
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.findings import Finding, Location
from webvigil.core.orchestrator import FINDINGS_PER_CHECK_CAP, _cap_findings
from webvigil.core.target import Target
from webvigil.crawler.forms import extract_forms
from webvigil.http import tls_probe
from webvigil.http.client import HttpClient, Response
from webvigil.http.tls_probe import TlsProbeResult, _unreachable

# Seconds one call may take. The bounded code finishes these inputs in well under a second.
_BUDGET_S = 5.0
# Characters of a probe body in the cost tests: what the HTTP layer lets through is 10 MiB, and a
# fraction of that is already far more than an unbounded pattern could read in the budget.
_PROBE_SIZE = 1024 * 1024
# Items listed on one page in the cap tests.
_LISTED = PER_PAGE_FINDINGS_CAP * 5


def _timed(call: object, *args: object, **kwargs: object) -> float:
    """
    Args:
        call (object): A callable.
        *args (object): Its positional arguments.
        **kwargs (object): Its keyword arguments.

    Returns:
        float: Seconds the call took.
    """
    started = time.perf_counter()
    call(*args, **kwargs)  # type: ignore[operator]
    return time.perf_counter() - started


# ---------------------------------------------------------------------------
# The probe validators: a capped head, bounded patterns
# ---------------------------------------------------------------------------


def _content_validators() -> list[Validator]:
    """
    Returns:
        list[Validator]: Every catalogue validator that matches the body against a pattern.
    """
    return [entry.validator for entry in load_catalogue() if entry.validator.content is not None]


@pytest.mark.parametrize(
    "unit",
    [
        pytest.param("\n", id="line-breaks"),
        pytest.param(" ", id="spaces"),
        pytest.param("Index of ", id="listing-title"),
        pytest.param("a=", id="assignments"),
        pytest.param("a:", id="colon-pairs"),
        pytest.param("1", id="digits"),
    ],
)
def test_every_probe_validator_reads_a_long_body_quickly(unit: str) -> None:
    """Each content validator, on a long run of the pieces its repetitions follow."""
    body = unit * (_PROBE_SIZE // len(unit))
    worst = max(
        _timed(validator.passes, body=body, raw=b"", content_type="text/plain")
        for validator in _content_validators()
    )
    assert worst < _BUDGET_S


def test_a_probe_validator_reads_only_the_head_of_a_body() -> None:
    """A marker inside the first ``_SCAN_MAX`` characters counts; one past it does not."""
    validator = Validator(content=re.compile("MARKER"))
    inside = "." * (_SCAN_MAX - 6) + "MARKER"
    past = "." * _SCAN_MAX + "MARKER"
    assert validator.passes(body=inside, raw=b"", content_type="text/plain")
    assert not validator.passes(body=past, raw=b"", content_type="text/plain")


# ---------------------------------------------------------------------------
# The JSON redaction: only what the evidence keeps is scanned
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "unit",
    [
        pytest.param("eyJ_", id="token-prefixes"),
        pytest.param("xoxb-", id="slack-prefixes"),
        pytest.param("-----BEGIN PRIVATE KEY-----", id="key-headers"),
    ],
)
def test_the_json_redaction_reads_long_strings_quickly(unit: str) -> None:
    """One long string, and many short ones, of the pieces the secret pattern starts with."""
    long_string = json.dumps({"config": unit * (_PROBE_SIZE // len(unit))})
    many_strings = json.dumps([unit * 40] * (_PROBE_SIZE // (len(unit) * 40)))
    assert _timed(redaction.apply, "json-env", long_string) < _BUDGET_S
    assert _timed(redaction.apply, "json-env", many_strings) < _BUDGET_S


def test_a_string_longer_than_the_evidence_is_masked_whole() -> None:
    """A string the evidence could not hold is replaced by the mask, not scanned and cut."""
    secret = "s3cr3t-" * 1000
    redacted = redaction.apply("json-env", json.dumps({"note": secret}))
    assert "s3cr3t" not in redacted
    assert json.loads(redacted) == {"note": "***"}


def test_a_secret_shape_in_the_first_strings_is_still_masked() -> None:
    """The budget leaves the strings the evidence shows scanned as before."""
    token = "AKIA" + "A" * 16
    redacted = redaction.apply("json-env", json.dumps({"name": "app", "aws": token}))
    assert token not in redacted
    assert json.loads(redacted)["name"] == "app"


# ---------------------------------------------------------------------------
# One finding per listed item: capped per page, with a note
# ---------------------------------------------------------------------------


def _assert_capped(findings: list[Finding]) -> None:
    """
    Args:
        findings (list[Finding]): A check's findings on a page that lists ``_LISTED`` items.
    """
    assert len(findings) == PER_PAGE_FINDINGS_CAP
    notes = [e.content for e in findings[-1].evidence if e.label == "note"]
    assert notes and notes[0].startswith("this page lists more ")
    assert all(e.label != "note" for f in findings[:-1] for e in f.evidence)


async def test_cross_origin_resources_without_integrity_are_capped_per_page() -> None:
    """A page that loads many CDN scripts without SRI yields the cap, and says there are more."""
    html = "".join(f'<script src="https://cdn.other/{i}.js"></script>' for i in range(_LISTED))
    ctx = make_context(make_page(url="https://shop.example/", text=html))
    _assert_capped(await SriMissingCheck().run(ctx))


async def test_mixed_content_resources_are_capped_per_page() -> None:
    """An HTTPS page that loads many images over HTTP yields the cap, and says there are more."""
    html = "".join(f'<img src="http://img.other/{i}.png">' for i in range(_LISTED))
    ctx = make_context(make_page(url="https://shop.example/", text=html))
    _assert_capped(await MixedContentCheck().run(ctx))


async def test_session_identifiers_in_links_are_capped_per_page() -> None:
    """A page with many links that carry a session identifier yields the cap, and a note."""
    html = "".join(f'<a href="/item/{i}?sid=abc{i}">x</a>' for i in range(_LISTED))
    ctx = make_context(make_page(url="https://shop.example/", text=html))
    _assert_capped(await SessionIdInUrlCheck().run(ctx))


async def test_weak_cookies_are_capped_per_page() -> None:
    """A page that sets many cookies with no attributes yields the cap, and says there are more."""
    page = make_page(url="https://shop.example/", set_cookies=[f"c{i}=v" for i in range(_LISTED)])
    findings = await CookieFlagsCheck().run(make_context(page))
    assert len(findings) == PER_PAGE_FINDINGS_CAP
    notes = [e.content for e in findings[-1].evidence if e.label == "note"]
    assert notes == [
        "this page lists more cookies with weak attributes; "
        f"the first {PER_PAGE_FINDINGS_CAP} are reported"
    ]


def _hostile_page(index: int) -> Page:
    """
    Args:
        index (int): Keeps every item of the page distinct from the other pages' items.

    Returns:
        Page: An HTTPS page that lists ``_LISTED`` of every kind of item a check reports one
            finding for: cookies, cross-origin and plain-HTTP resources, links with a session
            identifier, private addresses, forms.
    """
    items = []
    for i in range(_LISTED):
        key = f"{index}-{i}"
        items.append(
            f'<script src="https://cdn.other/{key}.js"></script>'
            f'<img src="http://img.other/{key}.png">'
            f'<a href="/item/{key}?sid=abc{i}">x</a>'
            f"<p>10.{index}.{i // 250}.{i % 250 + 1}</p>"
            f'<form method="post" action="/f/{key}"><input name="q"></form>'
        )
    cookies = [f"c{index}x{i}=v" for i in range(_LISTED)]
    cookies += [f"sid{index}x{i}=a{i}" for i in range(_LISTED)]
    return make_page(
        url=f"https://shop.example/p{index}",
        set_cookies=cookies,
        text="<html><body>" + "".join(items) + "</body></html>",
    )


async def test_no_check_keeps_one_finding_per_listed_item(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Every registered check, on pages that list many items of every kind, stays within the cap.

    A check that sends its own request gets the same hostile page back; the TLS handshake is the
    one thing not played (its findings are about the one certificate, not a listed item).
    """

    async def _offline(*_args: object, **_kwargs: object) -> TlsProbeResult:
        return _unreachable(OSError("offline test"))

    monkeypatch.setattr(tls_probe, "probe", _offline)
    pages = tuple(_hostile_page(i) for i in range(3))
    target = Target.parse("https://shop.example/")

    def _answer(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers=list(pages[0].headers.multi_items()), text=pages[0].text)

    config = ScanConfig()
    http = HttpClient(target, config, transport=HandlerTransport(_answer))
    ctx = make_context(
        pages[0], pages=pages, http=http, config=config, forms=extract_forms(pages, target)
    )
    ceiling = PER_PAGE_FINDINGS_CAP * len(pages)
    over: dict[str, int] = {}
    async with http:
        for check_cls in all_checks():
            findings = await check_cls().run(ctx)
            if len(findings) > ceiling:
                over[check_cls.id] = len(findings)
    assert over == {}


def test_a_check_keeps_at_most_the_cap_of_distinct_findings() -> None:
    """Past ``FINDINGS_PER_CHECK_CAP`` distinct findings the rest are dropped, and that is said."""
    many = [_finding(i) for i in range(FINDINGS_PER_CHECK_CAP + 10)]
    kept, cut = _cap_findings(many)
    assert len(kept) == FINDINGS_PER_CHECK_CAP and cut
    assert kept == many[:FINDINGS_PER_CHECK_CAP]


def test_duplicates_do_not_count_against_the_cap() -> None:
    """Exactly the cap of distinct findings, each repeated, is kept whole and nothing is cut."""
    distinct = [_finding(i) for i in range(FINDINGS_PER_CHECK_CAP)]
    kept, cut = _cap_findings(distinct + distinct)
    assert kept == distinct and not cut


def _finding(index: int) -> Finding:
    """
    Args:
        index (int): Makes the finding's fingerprint distinct.

    Returns:
        Finding: A minimal finding of the cookie check.
    """
    return CookieFlagsCheck().finding(
        title="t",
        description="d",
        remediation="r",
        location=Location(url=f"https://shop.example/{index}"),
        dedup_key=str(index),
    )


async def test_a_page_under_the_cap_carries_no_note() -> None:
    """Below the cap, every item is reported and nothing is added."""
    html = '<script src="https://cdn.other/a.js"></script>'
    ctx = make_context(make_page(url="https://shop.example/", text=html))
    findings = await SriMissingCheck().run(ctx)
    assert len(findings) == 1
    assert all(e.label != "note" for e in findings[0].evidence)


# ---------------------------------------------------------------------------
# The open-redirect detector reads a long body quickly
# ---------------------------------------------------------------------------


def _response(text: str) -> Response:
    """
    Args:
        text (str): The response body.

    Returns:
        Response: A 200 HTML response with that body and no redirect.
    """
    return Response(
        url="https://shop.example/",
        requested_url="https://shop.example/",
        status_code=200,
        headers=httpx.Headers({"content-type": "text/html"}),
        text=text,
        content=b"",
        elapsed_ms=0.0,
    )


@pytest.mark.parametrize(
    "unit",
    [
        pytest.param("http-equiv=refresh ", id="meta-refresh"),
        pytest.param("location='", id="location-assignment"),
    ],
)
def test_the_redirect_detector_reads_a_long_body_quickly(unit: str) -> None:
    """Long runs of the start of the body patterns, with no sentinel host after them."""
    body = unit * (_PROBE_SIZE // len(unit))
    assert _timed(_honoured, _response(body)) < _BUDGET_S
