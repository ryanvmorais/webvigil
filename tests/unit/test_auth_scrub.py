"""
scrub_result — hide the login's secrets from a finished scan — spec 019 RF-11, ADR-9.

Results are built with the shared helpers and then given a secret in every free-text field;
the observable is the result that comes back. The cases that matter: every field a target can
reflect into, every spelling a target echoes with, structural fields that must never change
(a password of ``high`` must not rewrite a severity), and the 4-character floor.
"""

from __future__ import annotations

import html
import json
from urllib.parse import quote, quote_plus

import pytest

from tests.support import make_finding, make_result
from webvigil.auth.scrub import (
    MIN_SECRET_LENGTH,
    REDACTED,
    looks_like_session_value,
    scrub_result,
)
from webvigil.core.findings import EvidenceItem, Severity
from webvigil.core.result import CheckError, ScanResult
from webvigil.core.technology import DetectionMethod, Technology

_SECRET = "hunter2-pw"


def _leaky(secret: str = _SECRET) -> ScanResult:
    """
    Args:
        secret (str): The value planted in every free-text field.

    Returns:
        ScanResult: One finding, one technology, one check error and one warning, each
            carrying ``secret``.
    """
    finding = make_finding(url=f"https://example.com/p?sid={secret}", param=None).model_copy(
        update={
            "title": f"title {secret}",
            "description": f"description {secret}",
            "remediation": f"remediation {secret}",
            "evidence": (EvidenceItem(label="body", content=f"... {secret} ..."),),
        }
    )
    finding = finding.model_copy(
        update={"location": finding.location.model_copy(update={"cookie": f"sid={secret}"})}
    )
    tech = Technology(
        name="jquery",
        version="1.0",
        detection=DetectionMethod.FILENAME,
        source_url=f"https://example.com/a.js?k={secret}",
    )
    error = CheckError(check_id="x.y", message=f"boom {secret}", traceback=f"tb {secret}")
    return make_result(finding, errors=[error], warnings=[f"warning {secret}"], technologies=[tech])


def _all_text(result: ScanResult) -> str:
    """
    Args:
        result (ScanResult): A scan result.

    Returns:
        str: Its JSON, to ask "does the secret appear anywhere".
    """
    return result.model_dump_json()


def test_every_free_text_field_is_scrubbed() -> None:
    """Title, description, remediation, evidence, location, error, technology and warning."""
    scrubbed = scrub_result(_leaky(), [_SECRET])

    assert _SECRET not in _all_text(scrubbed)
    (finding,) = scrubbed.findings
    assert finding.title == f"title {REDACTED}"
    assert finding.evidence[0].content == f"... {REDACTED} ..."
    assert finding.location.cookie == f"sid={REDACTED}"
    assert finding.location.url.endswith(f"sid={REDACTED}")
    assert scrubbed.warnings[:-1] == (f"warning {REDACTED}",)
    assert scrubbed.errors[0].traceback == f"tb {REDACTED}"
    assert scrubbed.technologies[0].source_url.endswith(f"k={REDACTED}")


def test_every_spelling_a_target_echoes_is_scrubbed() -> None:
    """Raw, JSON-escaped, percent-encoded and form-encoded copies all go."""
    secret = 'p@ss "w d"&x'
    spellings = [secret, json.dumps(secret)[1:-1], quote(secret, safe=""), quote_plus(secret)]
    result = make_result(
        make_finding().model_copy(update={"description": " | ".join(spellings)}),
        warnings=[f"echo {spelling}" for spelling in spellings],
    )

    scrubbed = scrub_result(result, [secret])

    for spelling in spellings:
        assert spelling not in _all_text(scrubbed).replace("\\\\", "\\"), spelling
    assert scrubbed.findings[0].description == " | ".join([REDACTED] * len(spellings))


def test_a_secret_that_is_a_structural_value_never_rewrites_structure() -> None:
    """A password of ``high`` / ``passive`` leaves severity, mode, ids and fingerprints alone."""
    result = make_result(make_finding(severity=Severity.HIGH, check_id="http.headers.csp"))
    scrubbed = scrub_result(result, ["high", "passive", "headers"])

    assert scrubbed.findings[0].severity is Severity.HIGH
    assert scrubbed.findings[0].check_id == "http.headers.csp"
    assert scrubbed.findings[0].fingerprint == result.findings[0].fingerprint
    assert scrubbed.metadata == result.metadata
    ScanResult.model_validate_json(scrubbed.model_dump_json())  # still a valid result


def test_a_scrubbed_result_keeps_its_fingerprints() -> None:
    """A scrub never changes a fingerprint, so dedup and diffs between runs still work."""
    result = _leaky()
    scrubbed = scrub_result(result, [_SECRET])
    assert [f.fingerprint for f in scrubbed.findings] == [f.fingerprint for f in result.findings]


def test_secrets_under_the_floor_are_left_alone() -> None:
    """Under 4 characters nothing is replaced; with nothing to scrub the result is returned."""
    short = "a" * (MIN_SECRET_LENGTH - 1)
    result = _leaky(short)

    scrubbed = scrub_result(result, [short, ""])
    assert scrubbed.findings == result.findings
    assert scrubbed.warnings[-1].startswith("1 configured credential value shorter than 4")
    assert scrub_result(result, []) is result


def test_a_secret_containing_another_is_replaced_whole() -> None:
    """The longer secret wins, so no fragment of it is left behind."""
    result = make_result(warnings=["x abcdefgh y"])
    scrubbed = scrub_result(result, ["abcd", "abcdefgh"])
    assert scrubbed.warnings[0] == f"x {REDACTED} y"


def test_html_escaped_and_lower_case_percent_echoes_are_scrubbed() -> None:
    """An HTML page shows ``&amp;`` and ``&quot;``; some servers write ``%2f``, not ``%2F``."""
    secret = 'a&b"c/d<e'
    spellings = [html.escape(secret), html.escape(secret, quote=False), quote(secret, safe="")]
    spellings.append(spellings[-1].lower())
    result = make_result(make_finding().model_copy(update={"description": " | ".join(spellings)}))

    scrubbed = scrub_result(result, [secret])

    assert scrubbed.findings[0].description == " | ".join([REDACTED] * len(spellings))


def test_references_and_technology_names_are_scrubbed() -> None:
    """A reference URL, a technology name, version or advisory can carry a reflected value."""
    finding = make_finding().model_copy(
        update={"references": (f"https://example.com/doc?t={_SECRET}",)}
    )
    tech = Technology(
        name=f"app-{_SECRET}",
        version=f"1.0-{_SECRET}",
        detection=DetectionMethod.FILENAME,
        source_url="https://example.com/a.js",
        advisories=(f"X-{_SECRET}",),
    )
    scrubbed = scrub_result(make_result(finding, technologies=[tech]), [_SECRET])
    assert _SECRET not in _all_text(scrubbed)


def test_a_redaction_is_counted_in_a_warning() -> None:
    """A redaction is visible: the last warning says how many fields were changed."""
    scrubbed = scrub_result(_leaky(), [_SECRET])
    assert scrubbed.warnings[-1].startswith("the report hides a credential or session value in")
    assert scrub_result(make_result(), [_SECRET]).warnings == ()  # nothing hidden, no warning


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("p7k2m9q4r1s8t3v6w5x0y2z4ab", True),  # PHPSESSID: lower case and digits
        ("8F3A9C1D2E4B6A7C9D0E1F2A3B4C5D6E", True),  # JSESSIONID: upper-case hex
        ("eyJhbGciOiJIUzI1NiJ9.e30.sig", True),
        ("evidence", False),  # a word
        ("https://", False),  # a URL fragment
        ("abc1234", False),  # under 8 characters
    ],
)
def test_only_a_session_looking_value_from_the_target_is_scrubbable(
    value: str, expected: bool
) -> None:
    """The target picks its cookie values, so only one shaped like a session id counts."""
    assert looks_like_session_value(value) is expected


def test_a_target_cookie_of_a_common_word_cannot_blank_the_report() -> None:
    """A hostile site that sets ``sid=evidence`` does not hide the findings' evidence."""
    result = make_result(
        make_finding().model_copy(update={"title": "evidence of https://example.com/"})
    )
    assert scrub_result(result, [], issued=["evidence", "https://"]) is result
    issued = "p7k2m9q4r1s8t3v6w5x0"
    leaky = make_result(make_finding().model_copy(update={"title": f"sid {issued}"}))
    assert scrub_result(leaky, [], issued=[issued]).findings[0].title == f"sid {REDACTED}"


def test_a_given_secret_is_scrubbed_even_when_it_is_a_plain_word() -> None:
    """What the user gave is always hidden: the session-id shape applies to the target's values."""
    result = make_result(warnings=["echo swordfish"])
    assert scrub_result(result, ["swordfish"]).warnings[0] == f"echo {REDACTED}"
