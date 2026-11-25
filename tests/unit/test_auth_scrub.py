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
from collections.abc import Callable
from urllib.parse import quote, quote_plus

import pytest

from tests.support import make_finding, make_result
from webvigil.auth.scrub import (
    MIN_SECRET_LENGTH,
    REDACTED,
    looks_like_session_value,
    scrub_result,
)
from webvigil.checks.envelope.scanner import _SENTINEL, EnvelopeScanner
from webvigil.checks.injection.detect import cmdi, ssrf, xss
from webvigil.checks.upload import scanner as upload
from webvigil.core.findings import EvidenceItem, Severity
from webvigil.core.output import _spellings
from webvigil.core.result import CheckError, ScanResult
from webvigil.core.secrets import Secret, SecretKind
from webvigil.core.technology import DetectionMethod, Technology

_SECRET = "hunter2-pw"


def _given(*values: str, kind: SecretKind = SecretKind.PASSWORD) -> list[Secret]:
    """
    Args:
        *values (str): Values the user gave.
        kind (SecretKind): Their kind. Defaults to ``PASSWORD``.

    Returns:
        list[Secret]: One secret per value.
    """
    return [Secret(value, kind=kind) for value in values]


def _issued(*values: str) -> list[Secret]:
    """
    Args:
        *values (str): Values the target issued.

    Returns:
        list[Secret]: One ``SESSION`` secret per value.
    """
    return [Secret(value, kind=SecretKind.SESSION) for value in values]


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
    scrubbed = scrub_result(_leaky(), _given(_SECRET))

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

    scrubbed = scrub_result(result, _given(secret))

    for spelling in spellings:
        assert spelling not in _all_text(scrubbed).replace("\\\\", "\\"), spelling
    assert scrubbed.findings[0].description == " | ".join([REDACTED] * len(spellings))


def test_a_secret_that_is_a_structural_value_never_rewrites_structure() -> None:
    """A password of ``high`` / ``passive`` leaves severity, mode, ids and fingerprints alone."""
    result = make_result(make_finding(severity=Severity.HIGH, check_id="http.headers.csp"))
    scrubbed = scrub_result(result, _given("high", "passive", "headers"))

    assert scrubbed.findings[0].severity is Severity.HIGH
    assert scrubbed.findings[0].check_id == "http.headers.csp"
    assert scrubbed.findings[0].fingerprint == result.findings[0].fingerprint
    assert scrubbed.metadata == result.metadata
    ScanResult.model_validate_json(scrubbed.model_dump_json())  # still a valid result


def test_a_scrubbed_result_keeps_its_fingerprints() -> None:
    """A scrub never changes a fingerprint, so dedup and diffs between runs still work."""
    result = _leaky()
    scrubbed = scrub_result(result, _given(_SECRET))
    assert [f.fingerprint for f in scrubbed.findings] == [f.fingerprint for f in result.findings]


def test_secrets_under_the_floor_are_left_alone() -> None:
    """Under 4 characters nothing is replaced; with nothing to scrub the result is returned."""
    short = "a" * (MIN_SECRET_LENGTH - 1)
    result = _leaky(short)

    scrubbed = scrub_result(result, _given(short, ""))
    assert scrubbed.findings == result.findings
    assert scrubbed.warnings[-1].startswith("1 configured credential value shorter than 4")
    assert scrub_result(result, _given()) is result
    # at the floor a value is scrubbed, and is not called short
    floor = "b" * MIN_SECRET_LENGTH
    at_floor = scrub_result(_leaky(floor), _given(floor))
    assert floor not in at_floor.model_dump_json()
    assert not any("shorter than" in warning for warning in at_floor.warnings)


def test_a_secret_containing_another_is_replaced_whole() -> None:
    """The longer secret wins, so no fragment of it is left behind."""
    result = make_result(warnings=["x abcdefgh y"])
    scrubbed = scrub_result(result, _given("abcd", "abcdefgh"))
    assert scrubbed.warnings[0] == f"x {REDACTED} y"


def test_html_escaped_and_lower_case_percent_echoes_are_scrubbed() -> None:
    """An HTML page shows ``&amp;`` and ``&quot;``; some servers write ``%2f``, not ``%2F``."""
    secret = 'a&b"c/d<e'
    spellings = [html.escape(secret), html.escape(secret, quote=False), quote(secret, safe="")]
    spellings.append(spellings[-1].lower())
    result = make_result(make_finding().model_copy(update={"description": " | ".join(spellings)}))

    scrubbed = scrub_result(result, _given(secret))

    assert scrubbed.findings[0].description == " | ".join([REDACTED] * len(spellings))


@pytest.mark.parametrize(
    "spelling",
    ["Caf%E9Token%2012", "Caf%e9Token%2012", "Caf%E9Token+12", "Caf%e9Token+12"],
    ids=["percent", "percent-lower", "form", "form-lower"],
)
@pytest.mark.parametrize("kind", ["given", "issued"])
def test_a_latin1_percent_echo_is_scrubbed(spelling: str, kind: str) -> None:
    """A page in Latin-1 writes ``é`` as ``%E9``, the same secret under other bytes."""
    secret = "CaféToken 12"
    result = make_result(make_finding().model_copy(update={"title": f"echo {spelling}"}))

    scrubbed = (
        scrub_result(result, _given(secret))
        if kind == "given"
        else scrub_result(result, _issued(secret))
    )

    assert scrubbed.findings[0].title == f"echo {REDACTED}"


def test_a_secret_outside_latin1_keeps_its_utf8_spelling() -> None:
    """Latin-1 cannot encode it: that spelling is skipped and the UTF-8 one still goes."""
    secret = "日本語Token12"
    echo = quote(secret, safe="")
    result = make_result(make_finding().model_copy(update={"title": f"echo {echo}"}))

    assert scrub_result(result, _given(secret)).findings[0].title == f"echo {REDACTED}"


def test_a_target_value_that_is_no_session_id_cannot_blank_its_percent_form() -> None:
    """The session-id shape is judged on the value, so a URL's escapes stay in the report."""
    title = "page /%E9%E9%E9%E9 and /%C3%A9%C3%A9%C3%A9%C3%A9"
    result = make_result(make_finding().model_copy(update={"title": title}))

    assert scrub_result(result, _issued("éééé")) is result


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
    scrubbed = scrub_result(make_result(finding, technologies=[tech]), _given(_SECRET))
    assert _SECRET not in _all_text(scrubbed)


def test_a_redaction_is_counted_in_a_warning() -> None:
    """A redaction is visible: the last warning says how many fields were changed."""
    scrubbed = scrub_result(_leaky(), _given(_SECRET))
    assert scrubbed.warnings[-1].startswith("the report hides a credential or session value in")
    assert scrub_result(make_result(), _given(_SECRET)).warnings == ()  # nothing hidden, no warning


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
    assert scrub_result(result, _issued("evidence", "https://")) is result
    issued = "p7k2m9q4r1s8t3v6w5x0"
    leaky = make_result(make_finding().model_copy(update={"title": f"sid {issued}"}))
    assert scrub_result(leaky, _issued(issued)).findings[0].title == f"sid {REDACTED}"


def test_a_given_secret_is_scrubbed_even_when_it_is_a_plain_word() -> None:
    """What the user gave is always hidden: the session-id shape applies to the target's values."""
    result = make_result(warnings=["echo swordfish"])
    assert scrub_result(result, _given("swordfish")).warnings[0] == f"echo {REDACTED}"


@pytest.mark.parametrize(
    ("secret", "quoted"),
    [
        ("pässword", r"p\xc3\xa4ssword"),
        ("pässword", r"p\xe4ssword"),
        ("€uro-key", r"\xe2\x82\xacuro-key"),
        ("pass\x01word", r"pass\x01word"),
        ("pass\tword", r"pass\tword"),
        ("back\\slash", r"back\\slash"),
        ("it's\"both", "it\\'s\"both"),
    ],
    ids=["utf-8", "latin-1", "outside-latin-1", "control", "tab", "backslash", "both-quotes"],
)
def test_a_value_quoted_as_bytes_is_scrubbed(secret: str, quoted: str) -> None:
    """A library's error quotes a value as the ``repr`` of its bytes, with its own escapes."""
    result = make_result(
        make_finding().model_copy(update={"description": f"refused b'{quoted}' here"})
    )

    scrubbed = scrub_result(result, _given(secret))

    assert scrubbed.findings[0].description == f"refused b'{REDACTED}' here"


# ---------------------------------------------------------------------------
# The kind of a secret decides its treatment (spec 024, RF-07)
# ---------------------------------------------------------------------------


def test_a_header_value_is_also_scrubbed_without_its_scheme() -> None:
    """A ``HEADER`` secret hides ``Bearer <token>`` and the token on its own."""
    token = "t0ken-abc123"
    result = make_result(
        make_finding().model_copy(
            update={"title": f"sent Bearer {token}", "description": f"the page echoed {token}"}
        )
    )
    scrubbed = scrub_result(result, _given(f"Bearer {token}", kind=SecretKind.HEADER))
    assert scrubbed.findings[0].title == f"sent {REDACTED}"
    assert scrubbed.findings[0].description == f"the page echoed {REDACTED}"
    # the scheme rule is the header's: a password with a space is hidden whole, never in parts
    as_password = scrub_result(result, _given(f"Bearer {token}"))
    assert as_password.findings[0].title == f"sent {REDACTED}"
    assert as_password.findings[0].description == f"the page echoed {token}"
    # spaces between the scheme and the credential are not part of the credential
    spaced = scrub_result(result, _given(f"Bearer   {token}", kind=SecretKind.HEADER))
    assert spaced.findings[0].description == f"the page echoed {REDACTED}"
    # a value with no space is one text, and nothing empty is scrubbed
    bare = scrub_result(result, _given(token, kind=SecretKind.HEADER))
    assert bare.findings[0].title == f"sent Bearer {REDACTED}"


def test_a_cookie_value_is_scrubbed_without_the_spaces_around_it() -> None:
    """A cookie written ``sid = value`` is held as `` value`` and scrubbed as ``value``."""
    result = make_result(
        make_finding().model_copy(update={"description": "the page echoed c00kie-v4lue."})
    )
    scrubbed = scrub_result(result, _given(" c00kie-v4lue ", kind=SecretKind.COOKIE))
    assert scrubbed.findings[0].description == f"the page echoed {REDACTED}."
    # positive control: the same value with its spaces, as a password, is not in the text
    assert scrub_result(result, _given(" c00kie-v4lue ")).findings == result.findings


def test_a_short_header_credential_is_counted_and_a_short_session_value_is_not() -> None:
    """The warning counts what the user gave, the token without its scheme included."""
    result = make_result(make_finding().model_copy(update={"description": "nothing to hide"}))
    header = scrub_result(result, _given("Bearer ab", kind=SecretKind.HEADER))
    assert header.warnings == (
        "1 configured credential value shorter than 4 characters cannot be redacted from the "
        "report",
    )
    # what the target issued is never the user's to fix, so it is never counted
    assert scrub_result(result, _issued("ab")) is result


# ---------------------------------------------------------------------------
# A secret split by a check's cut (spec 025, RF-02)
# ---------------------------------------------------------------------------

_ANCHOR = "ANCHOR!"
_FILL = "~"


def _fragment_left(text: str, spelling: str) -> bool:
    """
    Args:
        text (str): A field of a scrubbed result.
        spelling (str): One spelling of the secret.

    Returns:
        bool: Whether any :data:`MIN_SECRET_LENGTH` consecutive characters of ``spelling``
            are in ``text``.
    """
    edge = MIN_SECRET_LENGTH
    return any(spelling[i : i + edge] in text for i in range(len(spelling) - edge + 1))


def _evidence_cuts() -> list[tuple[str, Callable[[str], str], str]]:
    """
    List the ways a check cuts evidence out of a body.

    Returns:
        list[tuple[str, Callable[[str], str], str]]: A name, a cut a check makes, and the
            anchor it centres on: the snippet helpers of the checks, and ``EvidenceItem.of``.
    """
    envelope = object.__new__(EnvelopeScanner)
    evidence_bound = 4096
    return [
        ("xss", lambda body: xss._snippet(body, _ANCHOR), _ANCHOR),
        ("cmdi", lambda body: cmdi._snippet(body, body.find(_ANCHOR)), _ANCHOR),
        ("ssrf", lambda body: ssrf._snippet(body, body.find(_ANCHOR)), _ANCHOR),
        ("upload", lambda body: upload._snippet(body, _ANCHOR), _ANCHOR),
        # no marker in the body: the helper keeps its first characters, with no ellipsis
        ("upload-unmarked", lambda body: upload._snippet(body, "absent"), _ANCHOR),
        ("envelope", lambda body: envelope._around_sentinel(body), _SENTINEL),
        (
            "EvidenceItem.of",
            lambda body: EvidenceItem.of("body", _FILL * (evidence_bound - 150) + body).content,
            _ANCHOR,
        ),
    ]


@pytest.mark.parametrize(
    ("cut", "anchor"),
    [(cut, anchor) for _, cut, anchor in _evidence_cuts()],
    ids=[name for name, _, _ in _evidence_cuts()],
)
def test_no_fragment_of_a_secret_a_check_cut_survives_the_scrub(
    cut: Callable[[str], str], anchor: str
) -> None:
    """
    A body holds the secret at every distance from the anchor, in every spelling a target echoes.

    Each snippet the check would quote goes into the evidence of one result, which is scrubbed
    once: no 4 characters of any spelling are left.
    """
    snippets: list[str] = []
    spellings = sorted(_spellings(_SECRET), key=len)
    for spelling in spellings:
        for pad in range(0, 260):
            for body in (
                anchor + _FILL * pad + spelling + _FILL * 300,  # cut after the anchor
                _FILL * 300 + spelling + _FILL * pad + anchor + _FILL * 300,  # cut before it
            ):
                snippet = cut(body)
                if spelling not in snippet and _fragment_left(snippet, spelling):
                    snippets.append(snippet)
    # positive control: the sweep did split a spelling, leaving 4 or more characters of it
    assert snippets
    evidence = tuple(EvidenceItem(label="body", content=s) for s in snippets)
    result = make_result(make_finding().model_copy(update={"evidence": evidence}))

    scrubbed = scrub_result(result, _given(_SECRET))

    for item, snippet in zip(scrubbed.findings[0].evidence, snippets, strict=True):
        # the redaction is longer than a fragment, so the field's bound can cut its end off
        assert item.content != snippet
        for spelling in spellings:
            assert not _fragment_left(item.content, spelling), (spelling, item.content)
    assert scrubbed.warnings[-1].startswith(
        f"the report hides a credential or session value in {len(snippets)} fields"
    )


def test_a_title_cut_without_a_marker_keeps_a_word_that_starts_like_the_secret() -> None:
    """Only evidence is matched at its edges: a title ending with ``hunt`` stays as written."""
    finding = make_finding().model_copy(
        update={
            "title": "Welcome hunt",
            "evidence": (EvidenceItem(label="body", content="Welcome hunt"),),
        }
    )

    scrubbed = scrub_result(make_result(finding), _given(_SECRET))

    assert scrubbed.findings[0].title == "Welcome hunt"
    # positive control: the same text as evidence ends where a check may have cut it
    assert scrubbed.findings[0].evidence[0].content == f"Welcome {REDACTED}"
