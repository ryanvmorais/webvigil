"""
Hostile content cannot stall the CLI, abort a scan or lose its result.

What a scanned site or a report file holds reaches error messages, parsers and writers. These
tests pin the size and the exact text of what is printed (never a clock), that a parser given
unreadable text behaves as if the resource were absent, and that a character UTF-8 cannot encode
does not cost the report. Sites are played by an in-process transport, so nothing leaves the
machine, the terminal is an in-memory console wide enough that Rich does not wrap, and what
yields such a character is a fixture these tests register for themselves.
"""

from __future__ import annotations

import codecs
import hashlib
import io
import json
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx2
import pytest
from pydantic import ValidationError
from rich.console import Console
from typer.testing import CliRunner

from tests.http_mock import HttpxMock
from tests.support import HandlerTransport, make_finding, make_result
from webvigil import reporting as reporting_mod
from webvigil.auth.login import Authenticator, Credentials
from webvigil.cli import _render
from webvigil.cli import app as app_mod
from webvigil.cli._exit import ExitCode
from webvigil.core import Orchestrator
from webvigil.core.config import LoginSection, ScanConfig
from webvigil.core.errors import LoginFailedError
from webvigil.core.findings import (
    Confidence,
    EvidenceItem,
    Finding,
    Location,
    Severity,
    compute_fingerprint,
)
from webvigil.core.result import CheckError, ScanResult
from webvigil.core.target import Target
from webvigil.core.technology import DetectionMethod, Technology
from webvigil.core.text import replace_surrogates, replace_surrogates_in
from webvigil.crawler import robots, sitemap
from webvigil.crawler.har import load_har
from webvigil.crawler.openapi import load_openapi
from webvigil.http import client as client_mod
from webvigil.http.client import HttpClient
from webvigil.reporting import get_reporter, load_result

runner = CliRunner()

# The ceiling of a terminal message, repeated here so a change to the constant fails a test.
_CEILING = 4096
_MARKER = "...[truncated]"
_LONE = "\ud800"
_REPLACED = "�"
_BASE = "http://demo.test/"
# The encoding of :func:`_test_codec`, and the byte it reads as the character above.
_FIXTURE_ENCODING = "webvigil_test_lone"
_LONE_BYTE = "\x01"
_FORMATS = ("json", "sarif", "html", "md")


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero the retry backoff so a failing request does not sleep."""
    monkeypatch.setattr(client_mod, "BACKOFF_BASE_S", 0.0)
    monkeypatch.setattr(client_mod, "BACKOFF_JITTER_S", 0.0)


class _LoneDecoder(codecs.IncrementalDecoder):
    """Reads each byte as itself, except :data:`_LONE_BYTE`, which becomes the character."""

    def decode(self, input: bytes, final: bool = False) -> str:
        """
        Args:
            input (bytes): The bytes to decode.
            final (bool): Whether they are the last ones. Defaults to ``False``.

        Returns:
            str: The decoded text.
        """
        return bytes(input).decode("latin-1").replace(_LONE_BYTE, _LONE)


@pytest.fixture(autouse=True)
def _test_codec() -> Iterator[None]:
    """Register :data:`_FIXTURE_ENCODING` for one test, and take it away afterwards."""

    def find(name: str) -> codecs.CodecInfo | None:
        if name != _FIXTURE_ENCODING:
            return None
        return codecs.CodecInfo(
            encode=codecs.latin_1_encode,
            decode=codecs.latin_1_decode,
            incrementaldecoder=_LoneDecoder,
            name=_FIXTURE_ENCODING,
        )

    codecs.register(find)
    yield
    codecs.unregister(find)


@pytest.fixture
def terminal(monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
    """
    Args:
        monkeypatch (pytest.MonkeyPatch): Swaps the renderer's console.

    Returns:
        io.StringIO: What the renderer prints, on a console too wide to wrap a line.
    """
    buffer = io.StringIO()
    console = Console(file=buffer, width=1_000_000, color_system=None, force_terminal=False)
    monkeypatch.setattr(_render, "_console", console)
    return buffer


def _encoded(text: str) -> bytes:
    """
    Args:
        text (str): Text that may hold an unpaired surrogate.

    Returns:
        bytes: ``text`` in :data:`_FIXTURE_ENCODING`, which decodes back to the same string.
    """
    return text.replace(_LONE, _LONE_BYTE).encode("latin-1")


def _site(pages: dict[str, tuple[bytes, str]]) -> Callable[[httpx2.Request], httpx2.Response]:
    """
    Args:
        pages (dict[str, tuple[bytes, str]]): ``path -> (body, content type)``.

    Returns:
        Callable[[httpx2.Request], httpx2.Response]: A target serving ``pages``, a plain home
            page at ``/`` unless given, and ``404`` for anything else.
    """

    def answer(request: httpx2.Request) -> httpx2.Response:
        path = request.url.path
        if path in pages:
            body, content_type = pages[path]
            return httpx2.Response(200, headers={"content-type": content_type}, content=body)
        if path == "/":
            return httpx2.Response(
                200, headers={"content-type": "text/html"}, text="<html><body>ok</body></html>"
            )
        return httpx2.Response(404, text="")

    return answer


async def _scan(httpx_mock: HttpxMock, pages: dict[str, tuple[bytes, str]]) -> ScanResult:
    """
    Args:
        httpx_mock (HttpxMock): The transport mock.
        pages (dict[str, tuple[bytes, str]]): What the target serves.

    Returns:
        ScanResult: A real Passive scan of that target.
    """
    httpx_mock.add_callback(_site(pages), is_reusable=True)
    config = ScanConfig().with_overrides(scan={"max_pages": 5}, http={"delay_ms": 0})
    return await Orchestrator(config).run(_BASE)


# ---------------------------------------------------------------------------
# A corrupt report file
# ---------------------------------------------------------------------------


def _report_document(findings: int = 0) -> dict[str, Any]:
    """
    Args:
        findings (int): How many findings the report holds. Defaults to none.

    Returns:
        dict[str, Any]: A valid JSON report, as a document a test can damage.
    """
    result = make_result(*(make_finding(dedup_key=str(n)) for n in range(findings)))
    document: dict[str, Any] = json.loads(get_reporter("json").render(result))
    return document


def _write(path: Path, document: object) -> Path:
    """
    Args:
        path (Path): Where to write.
        document (object): The JSON document.

    Returns:
        Path: ``path``.
    """
    path.write_text(json.dumps(document), "utf-8")
    return path


def test_a_corrupt_report_counts_its_errors_and_names_three_places_without_a_value(
    tmp_path: Path,
) -> None:
    """Five bad fields give one short exact line; the raw validation text had every value."""
    document = _report_document(findings=1)
    finding = document["findings"][0]
    finding["severity"] = finding["confidence"] = "VALUE-FROM-THE-FILE"
    finding["title"] = finding["description"] = finding["remediation"] = 12345
    path = _write(tmp_path / "scan.json", document)

    with pytest.raises(ValueError) as caught:
        load_result(path)

    assert str(caught.value) == (
        "not a valid WebVigil report: 5 errors, at findings[0].severity, "
        "findings[0].confidence, findings[0].title and 2 more"
    )
    # positive control: the validator's own text is what used to be printed, and it quotes them
    with pytest.raises(ValidationError) as raw:
        ScanResult.model_validate_json(path.read_bytes())
    assert str(raw.value).count("VALUE-FROM-THE-FILE") == 2


@pytest.mark.parametrize(
    ("kind", "errors"),
    [("many", 3), ("one", 1), ("not-json", 1)],
)
def test_a_refused_report_reads_its_error_list_once_and_without_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, errors: int
) -> None:
    """One list per failure, holding neither the input, the context nor a documentation URL."""
    many = _report_document(findings=1)
    bad = many["findings"][0]
    bad["title"] = bad["description"] = bad["remediation"] = 12345
    one = _report_document(findings=1)
    one["findings"][0]["severity"] = "not a severity"  # this error type carries a context
    content = {
        "many": json.dumps(many).encode(),
        "one": json.dumps(one).encode(),
        "not-json": b"TEXT-FROM-THE-FILE",
    }[kind]
    path = tmp_path / "scan.json"
    path.write_bytes(content)
    lists: list[list[Any]] = []
    real = reporting_mod._error_details

    def spy(exc: ValidationError) -> list[Any]:
        details = real(exc)
        lists.append(list(details))
        return list(details)

    monkeypatch.setattr(reporting_mod, "_error_details", spy)

    with pytest.raises(ValueError, match=r"^not a valid WebVigil report"):
        load_result(path)

    assert [len(found) for found in lists] == [errors]
    assert set(lists[0][0]) == {"type", "loc", "msg"}


def test_a_key_the_file_chose_is_left_out_of_the_place_named(tmp_path: Path) -> None:
    """Bad ``counts`` entries are named once, by their field: the keys are the file's content."""
    document = _report_document()
    document["metadata"]["counts"] = {"KEY-FROM-THE-FILE": "not a number", "OTHER-KEY": "nor this"}
    path = _write(tmp_path / "scan.json", document)

    with pytest.raises(ValueError) as caught:
        load_result(path)

    assert str(caught.value) == "not a valid WebVigil report: 2 errors, at metadata.counts"
    with pytest.raises(ValidationError) as raw:  # positive control: pydantic's path has the key
        ScanResult.model_validate_json(path.read_bytes())
    assert "KEY-FROM-THE-FILE" in str(raw.value)


def test_a_file_that_is_not_json_says_so(tmp_path: Path) -> None:
    """Text that does not parse gets one fixed line, with nothing of the file in it."""
    path = tmp_path / "scan.json"
    path.write_text("TEXT-FROM-THE-FILE", "utf-8")

    with pytest.raises(ValueError) as caught:
        load_result(path)

    assert str(caught.value) == "not a valid WebVigil report: the file is not valid JSON"


def test_a_report_that_is_not_an_object_names_the_top_level(tmp_path: Path) -> None:
    """A JSON value of the wrong shape has no field to name."""
    path = _write(tmp_path / "scan.json", ["VALUE-FROM-THE-FILE"])

    with pytest.raises(ValueError) as caught:
        load_result(path)

    assert str(caught.value) == "not a valid WebVigil report: 1 error, at the top level"


def test_a_report_from_a_newer_schema_keeps_its_message_within_a_bound(tmp_path: Path) -> None:
    """The upgrade advice survives; a version number as long as the file can write does not."""
    document = _report_document()
    document["schema_version"] = 2
    with pytest.raises(ValueError) as short:
        load_result(_write(tmp_path / "short.json", document))
    assert str(short.value) == (
        "this report uses schema 2, but this WebVigil reads up to schema 1: "
        "upgrade WebVigil to read it"
    )

    path = tmp_path / "long.json"
    text = json.dumps(_report_document()).replace(
        '"schema_version": 1', '"schema_version": 1' + "9" * 1000
    )
    path.write_text(text, "utf-8")
    with pytest.raises(ValueError) as long_version:
        load_result(path)
    assert str(long_version.value) == "this report uses schema 1" + "9" * 231 + _MARKER


def test_the_report_command_prints_the_short_line_and_exits_4(
    tmp_path: Path, terminal: io.StringIO
) -> None:
    """End to end: exit 4 and exactly one line, for a file with an error in every finding."""
    document = _report_document(findings=5)
    for finding in document["findings"]:
        finding["title"] = 12345
    path = _write(tmp_path / "scan.json", document)

    result = runner.invoke(app_mod.app, ["report", str(path), "--format", "md"])

    assert result.exit_code == ExitCode.OPERATIONAL == 4
    assert terminal.getvalue() == (
        f"error: could not read {path}: not a valid WebVigil report: 1 error, at "
        "findings[0].title\n"
    )


# ---------------------------------------------------------------------------
# A login page that declares too much
# ---------------------------------------------------------------------------


async def _login_error(page: str, **login: object) -> str:
    """
    Args:
        page (str): The login page's body.
        **login (object): Extra ``[auth.login]`` keys.

    Returns:
        str: The message the login failed with.
    """

    def answer(_request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, headers={"content-type": "text/html"}, text=page)

    target = Target.parse(_BASE)
    # the keywords vary by test and pydantic validates them, so ``Any`` is not worth spelling out
    section = LoginSection(url=f"{_BASE}signin", username="u", **login)  # type: ignore[arg-type]
    async with HttpClient(target, ScanConfig(), transport=HandlerTransport(answer)) as http:
        authenticator = Authenticator(http, target, section, Credentials("u", "password"))
        http.use_session(authenticator.session)
        with pytest.raises(LoginFailedError) as caught:
            await authenticator.login()
    return str(caught.value)


def _form(action: str, names: list[str], *, method: str = "get") -> str:
    """
    Args:
        action (str): The form's action.
        names (list[str]): Its text inputs.
        method (str): Its method. Defaults to ``get``.

    Returns:
        str: The form's HTML.
    """
    inputs = "".join(f'<input type="text" name="{name}">' for name in names)
    return f'<form method="{method}" action="{action}">{inputs}</form>'


async def test_a_login_page_with_many_forms_is_described_in_a_bounded_list() -> None:
    """Five forms, then how many were left out."""
    page = "".join(_form(f"/f{n}", ["a"]) for n in range(8))

    message = await _login_error(page)

    shown = "; ".join(f"GET http://demo.test/f{n}(a)" for n in range(5))
    assert message == (
        "no login form (a POST form with a password input) on http://demo.test/signin; "
        f"forms seen: {shown}; and 3 more form(s)"
    )


async def test_a_form_at_the_limit_is_listed_whole() -> None:
    """Exactly five forms of exactly ten fields lose nothing: the cut starts past the limit."""
    names = [f"f{n}" for n in range(10)]
    page = "".join(_form(f"/f{n}", names) for n in range(5))

    message = await _login_error(page)

    fields = ", ".join(names)
    shown = "; ".join(f"GET http://demo.test/f{n}({fields})" for n in range(5))
    assert message.endswith(f"forms seen: {shown}")


async def test_a_form_with_many_fields_and_long_names_is_described_in_a_bounded_list() -> None:
    """Ten names, each cut, then how many were left out; the action is cut as well."""
    long_name = "n" * 300
    names = [long_name, *(f"f{n}" for n in range(14))]
    action = "/" + "a" * 400
    page = _form(action, names)

    message = await _login_error(page)

    shown = ", ".join(["n" * 64 + _MARKER, *(f"f{n}" for n in range(9))])
    url = (f"http://demo.test{action}")[:256] + _MARKER
    assert message.endswith(f"forms seen: GET {url}({shown}, and 5 more)")


@pytest.mark.parametrize(
    ("login", "prefix", "suffix"),
    [
        ({"username_field": "absent"}, "username_field 'absent' is not in the login form (", ")"),
        ({"password_field": "absent"}, "password_field 'absent' is not in the login form (", ")"),
        ({}, "no username input in the login form (", "); set username_field"),
    ],
)
async def test_the_messages_about_a_chosen_form_list_a_bounded_set_of_names(
    login: dict[str, str], prefix: str, suffix: str
) -> None:
    """Each message built from the chosen form's names keeps the same bound."""
    kind = "hidden" if not login else "text"
    inputs = "".join(f'<input type="{kind}" name="f{n}">' for n in range(12))
    page = f'<form method="post" action="/p">{inputs}<input type="password" name="pw"></form>'

    message = await _login_error(page, **login)

    assert message == prefix + ", ".join(f"f{n}" for n in range(10)) + ", and 3 more" + suffix


# ---------------------------------------------------------------------------
# The central ceiling on terminal output
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("show", "prefix"), [(_render.error, "error: "), (_render.status, "")])
def test_a_long_message_is_cut_at_the_ceiling(
    terminal: io.StringIO, show: Callable[[str], None], prefix: str
) -> None:
    """Every line a caller prints stops at the ceiling and ends with the marker."""
    show("x" * (_CEILING * 3))

    assert terminal.getvalue() == prefix + "x" * _CEILING + _MARKER + "\n"


@pytest.mark.parametrize(("show", "prefix"), [(_render.error, "error: "), (_render.status, "")])
def test_a_message_at_the_ceiling_is_printed_whole(
    terminal: io.StringIO, show: Callable[[str], None], prefix: str
) -> None:
    """The positive control: what fits in the ceiling and the marker is not cut."""
    show("x" * (_CEILING + len(_MARKER)))

    assert terminal.getvalue() == prefix + "x" * (_CEILING + len(_MARKER)) + "\n"


def test_a_message_of_control_characters_is_cut_on_its_source(terminal: io.StringIO) -> None:
    """
    The bound counts what the message held, and the cut never splits an escape (spec 025, ADR-2).

    A control character prints as four, so the line can be four times the ceiling, and still
    stops after the ceiling's worth of characters of the message.
    """
    _render.status("\x01" * (_CEILING + len(_MARKER) + 1))

    assert terminal.getvalue() == "\\x01" * _CEILING + _MARKER + "\n"


def test_an_unencodable_character_in_a_message_is_replaced(terminal: io.StringIO) -> None:
    """A message that quotes one prints the replacement character."""
    _render.error(f"bad{_LONE}name")

    assert terminal.getvalue() == f"error: bad{_REPLACED}name\n"


@pytest.mark.parametrize(
    ("count", "listed", "tail"),
    [
        (100, 100, []),
        (101, 100, ["... and 1 more warning(s): a report (--format) has them all"]),
        (250, 100, ["... and 150 more warning(s): a report (--format) has them all"]),
    ],
)
def test_the_summary_lists_a_bounded_number_of_warnings(
    terminal: io.StringIO, count: int, listed: int, tail: list[str]
) -> None:
    """Up to the limit every warning is listed; past it the rest are counted."""
    warnings = [f"note {n}" for n in range(count)]

    _render.summary(make_result(warnings=warnings))

    lines = terminal.getvalue().splitlines()
    first = lines.index("warning: note 0")
    assert lines[first:] == [f"warning: note {n}" for n in range(listed)] + tail


def test_the_summary_bounds_each_line_it_builds_from_the_site(terminal: io.StringIO) -> None:
    """A finding's URL and a warning are cut; the report keeps them whole."""
    long_url = "https://example.com/" + "p" * (_CEILING * 2)
    finding = make_finding(url=long_url, header=None)

    _render.summary(make_result(finding, warnings=["w" * (_CEILING * 2)]))

    lines = terminal.getvalue().splitlines()
    assert f"warning: {'w' * _CEILING}{_MARKER}" in lines
    expected = f"http.headers.csp finding  {long_url[:_CEILING]}{_MARKER}"
    assert [line for line in lines if "http.headers.csp" in line] == [f"    MEDIUM  {expected}"]
    assert get_reporter("json").render(make_result(finding)).count(long_url) == 1


# ---------------------------------------------------------------------------
# Unreadable site text is a missing resource, not a dead scan
# ---------------------------------------------------------------------------


def test_a_sitemap_that_cannot_be_encoded_counts_as_absent() -> None:
    """The parser returns nothing for it, and the same document without the character parses."""
    template = "<urlset><url><loc>http://demo.test/page{}</loc></url></urlset>"

    assert sitemap.parse(template.format(_LONE)) == []
    assert sitemap.parse(template.format("")) == ["http://demo.test/page"]


async def test_a_scan_survives_a_sitemap_it_cannot_keep_as_text(httpx_mock: HttpxMock) -> None:
    """The scan finishes and reports, with the home page and nothing raised."""
    xml = f"<urlset><url><loc>{_BASE}page{_LONE}</loc></url></urlset>"
    pages = {"/sitemap.xml": (_encoded(xml), f"application/xml; charset={_FIXTURE_ENCODING}")}

    result = await _scan(httpx_mock, pages)

    assert result.metadata.pages_scanned >= 1
    sitemap_asked = [r for r in httpx_mock.get_requests() if r.url.path == "/sitemap.xml"]
    assert len(sitemap_asked) == 1  # the path under test ran


async def _robots(text: str) -> robots.Robots:
    """
    Args:
        text (str): The body of ``/robots.txt``.

    Returns:
        robots.Robots: It, parsed through the real loader.
    """

    def answer(_request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, headers={"content-type": "text/plain"}, text=text)

    target = Target.parse(_BASE)
    async with HttpClient(target, ScanConfig(), transport=HandlerTransport(answer)) as http:
        return await robots.load(http, target.origin, "webvigil")


@pytest.mark.parametrize("directive", ["Crawl-delay", "Request-rate", "crawl-DELAY "])
async def test_a_value_the_parser_cannot_convert_keeps_the_robots_rules(directive: str) -> None:
    """The file still loads and its rules still apply, not an allow-all."""
    digits = "9" * (sys.get_int_max_str_digits() + 1)
    value = f"{digits}/1" if directive == "Request-rate" else digits

    parsed = await _robots(f"User-agent: *\n{directive}: {value}\nDisallow: /private\n")

    assert parsed.can_fetch("webvigil", f"{_BASE}private") is False
    assert parsed.can_fetch("webvigil", f"{_BASE}public") is True


async def test_a_scan_survives_a_robots_value_it_cannot_convert(httpx_mock: HttpxMock) -> None:
    """End to end: the crawl goes on past that file."""
    digits = b"9" * (sys.get_int_max_str_digits() + 1)
    pages = {"/robots.txt": (b"User-agent: *\nCrawl-delay: " + digits + b"\n", "text/plain")}

    result = await _scan(httpx_mock, pages)

    assert result.metadata.pages_scanned == 1


# Rules as real sites write them, each with a URL it names and a URL of the same group it leaves
# alone.
_COMMON_RULES = [
    ("/odata/Products?$filter=Name", "/odata/Products?$filter=Name", "/odata/Orders"),
    ("/api/$metadata", "/api/$metadata", "/api/items"),
    ("/a$b$c", "/a$b$c", "/a"),
    ("/price$/list", "/price$/list", "/price"),
    ("/files/*.pdf", "/files/*.pdf", "/docs/page"),
    ("/search?q=*", "/search?q=*", "/about"),
    ("/end$", "/end", "/other"),
    ("/*.gif$", "/image.gif", "/other"),
    ("/discount/100%", "/discount/100%", "/discount/50"),
    ("/%7Euser/private", "/~user/private", "/~user/public"),
    ("/cart;jsessionid=1", "/cart;jsessionid=1", "/shop"),
    ("/ns:special", "/ns:special", "/ns"),
    ("/@scope/pkg", "/@scope/pkg", "/@scope/other"),
    ("/wiki/Foo_(bar)", "/wiki/Foo_(bar)", "/wiki/Foo"),
    ("/café/menu", "/café/menu", "/cafe/menu"),
    ("/日本語/", "/日本語/page", "/english/page"),
]


@pytest.mark.parametrize(("rule", "named", "other"), _COMMON_RULES, ids=lambda v: str(v))
async def test_a_common_rule_blocks_what_it_names_and_nothing_else(
    rule: str, named: str, other: str
) -> None:
    """Valid path characters never cost the group: another URL of it stays allowed."""
    parsed = await _robots(f"User-agent: *\nDisallow: {rule}\n")

    assert parsed.can_fetch("webvigil", f"https://example.com{other}") is True
    assert parsed.can_fetch("webvigil", f"https://example.com{named}") is False


async def test_a_url_the_parser_cannot_read_is_not_fetched() -> None:
    """A URL from an imported document decides nothing by accident: it is simply not fetched."""
    parsed = await _robots("User-agent: *\nDisallow: /private\n")

    assert parsed.can_fetch("webvigil", "https://[unclosed/page") is False
    assert parsed.can_fetch("webvigil", f"{_BASE}public") is True  # the rules were read


async def test_a_scan_survives_a_malformed_robots_rule(httpx_mock: HttpxMock) -> None:
    """End to end: the crawl goes on, under the rules of the group that applies to it."""
    body = "User-agent: other\nDisallow: //[marker\nUser-agent: *\nAllow: /\n"
    pages = {"/robots.txt": (body.encode(), "text/plain")}

    result = await _scan(httpx_mock, pages)

    assert result.metadata.pages_scanned == 1


async def _load_document(document: object) -> tuple[list[Any], list[str]]:
    """
    Args:
        document (object): The OpenAPI document the target serves.

    Returns:
        tuple[list[Any], list[str]]: The imported operations and the warnings.
    """

    def answer(_request: httpx2.Request) -> httpx2.Response:
        body = json.dumps(document).encode()
        return httpx2.Response(200, headers={"content-type": "application/json"}, content=body)

    target = Target.parse(_BASE)
    async with HttpClient(target, ScanConfig(), transport=HandlerTransport(answer)) as http:
        return await load_openapi(
            f"{_BASE}openapi.json", http=http, target=target, max_operations=10
        )


async def test_an_openapi_document_cannot_put_an_unencodable_character_in_a_request() -> None:
    """Its paths and parameters arrive clean, and the URL can be built."""
    document = {
        "openapi": "3.0.0",
        "paths": {
            f"/p{_LONE}": {
                "get": {
                    "parameters": [
                        {"name": f"q{_LONE}", "in": "query", "schema": {"type": "string"}}
                    ],
                }
            }
        },
    }

    operations, _warnings = await _load_document(document)

    assert [operation.url_template for operation in operations] == [f"{_BASE}p{_REPLACED}"]
    assert [name for name, _value in operations[0].query] == [f"q{_REPLACED}"]
    httpx2.URL(operations[0].url)  # the step that raised


@pytest.mark.parametrize(
    "document",
    [
        {"openapi": "3.0.0", "servers": [{"url": "http://[bad/x"}], "paths": {"/p": {"get": {}}}},
        {"swagger": "2.0", "host": "[bad", "schemes": ["http"], "paths": {"/p": {"get": {}}}},
    ],
    ids=["openapi", "swagger"],
)
async def test_a_malformed_server_url_falls_back_to_the_target(document: dict[str, Any]) -> None:
    """The import carries on from the target's origin and says so."""
    operations, warnings = await _load_document(document)

    assert [operation.url_template for operation in operations] == [f"{_BASE}p"]
    assert warnings == [
        "OpenAPI server URL is malformed; paths are resolved against http://demo.test"
    ]


async def test_a_well_formed_server_path_is_still_used() -> None:
    """The positive control of the fallback above: no warning, and the base path is kept."""
    document = {"openapi": "3.0.0", "servers": [{"url": "/v1"}], "paths": {"/p": {"get": {}}}}

    operations, warnings = await _load_document(document)

    assert [operation.url_template for operation in operations] == [f"{_BASE}v1/p"]
    assert warnings == []


def test_a_har_recording_cannot_put_an_unencodable_character_in_a_request(tmp_path: Path) -> None:
    """The recording's URL arrives clean."""
    entry = {
        "request": {"method": "GET", "url": f"{_BASE}a{_LONE}", "headers": [], "queryString": []},
        "response": {"status": 200, "headers": [], "content": {}},
    }
    path = _write(tmp_path / "a.har", {"log": {"entries": [entry]}})

    imported = load_har(str(path), target=Target.parse(_BASE), max_operations=10)

    assert [operation.url for operation in imported.operations] == [f"{_BASE}a{_REPLACED}"]


def test_the_document_walk_reaches_keys_values_and_any_depth() -> None:
    """Every string is clean, a clean value is untouched, and depth costs no recursion."""
    deep: list[Any] = [f"bottom{_LONE}"]
    bottom = deep
    for _ in range(sys.getrecursionlimit() * 3):
        deep = [deep]

    document = {f"k{_LONE}": [f"v{_LONE}", 1, None, {"inner": f"w{_LONE}"}], "ok": "é", "d": deep}
    assert replace_surrogates_in(document) is document

    assert document[f"k{_REPLACED}"] == [f"v{_REPLACED}", 1, None, {"inner": f"w{_REPLACED}"}]
    assert f"k{_LONE}" not in document
    assert document["ok"] == "é"
    assert bottom == [f"bottom{_REPLACED}"]
    assert replace_surrogates_in(f"s{_LONE}") == f"s{_REPLACED}"
    # let go of the deep list one level at a time
    while deep and isinstance(deep[0], list):
        deep = deep[0]


# ---------------------------------------------------------------------------
# A character UTF-8 cannot encode does not lose the report
# ---------------------------------------------------------------------------


def test_the_replacement_is_one_for_one_and_keeps_valid_text() -> None:
    """Only the unpaired code points change, so the length and every other character stay."""
    assert replace_surrogates(f"é{_LONE}ñ\udc00😀") == f"é{_REPLACED}ñ{_REPLACED}😀"
    assert replace_surrogates("plain") == "plain"
    # the neighbours of the surrogate range and the noncharacters all encode to UTF-8
    assert replace_surrogates("퟿￾￿") == "퟿￾￿"


async def test_the_decoder_never_hands_the_engine_an_unpaired_surrogate() -> None:
    """Such a body reads with the replacement; valid non-ASCII text reads as it was."""
    answers = {
        "/bad": (_encoded(f"a{_LONE}b"), f"text/plain; charset={_FIXTURE_ENCODING}"),
        "/good": ("aéb".encode(), "text/plain; charset=utf-8"),
    }
    target = Target.parse(_BASE)
    transport = HandlerTransport(_site(answers))
    async with HttpClient(target, ScanConfig(), transport=transport) as http:
        bad = await http.get(f"{_BASE}bad")
        good = await http.get(f"{_BASE}good")

    assert bad.text == f"a{_REPLACED}b"
    assert good.text == "aéb"


@pytest.mark.parametrize(
    "build",
    [
        lambda text: Location(url=text).url,
        lambda text: Location(url="u", param=text).param,
        lambda text: EvidenceItem(label=text, content="c").label,
        lambda text: EvidenceItem.of("l", text).content,
        lambda text: CheckError(check_id=text, message="m", traceback="t").check_id,
        lambda text: CheckError(check_id="c", message=text, traceback="t").message,
        lambda text: CheckError(check_id="c", message="m", traceback=text).traceback,
        lambda text: Technology(
            name=text, version=None, detection=DetectionMethod.URI, source_url="u"
        ).name,
        lambda text: make_result(warnings=[text]).warnings[0],
    ],
    ids=[
        "url",
        "name",
        "label",
        "evidence",
        "check-id",
        "message",
        "traceback",
        "technology",
        "warning",
    ],
)
def test_every_bounded_field_replaces_an_unpaired_surrogate(
    build: Callable[[str], str | None],
) -> None:
    """The field holds the replacement, and clean text goes through unchanged."""
    assert build(f"a{_LONE}b") == f"a{_REPLACED}b"
    assert build("aéb") == "aéb"


def test_a_cut_value_with_a_surrogate_is_still_clean() -> None:
    """Replacing and cutting compose, at the exact bound of the field."""
    item = EvidenceItem(label="l", content=_LONE * 5000)

    assert item.content == _REPLACED * 4096 + "\n...[truncated]"


def test_a_fingerprint_survives_a_surrogate_and_normal_ones_do_not_change() -> None:
    """A check's dedup key cannot raise here, and the hash of ordinary text is the same."""
    location = Location(url="https://example.com/", param="q")

    assert len(compute_fingerprint("check", location, f"key{_LONE}")) == 16
    # two keys that differ only in such a character stay two findings
    assert compute_fingerprint("check", location, "key\ud800") != compute_fingerprint(
        "check", location, "key\udc00"
    )
    ordinary = "\n".join(["check", "https://example.com/", "q", "key"])
    assert (
        compute_fingerprint("check", location, "key")
        == hashlib.sha256(ordinary.encode("utf-8")).hexdigest()[:16]
    )


def _hostile_result() -> ScanResult:
    """
    Returns:
        ScanResult: A result with an unpaired surrogate in every kind of text a report prints.
    """
    location = Location(url=f"https://example.com/{_LONE}", param=f"q{_LONE}")
    finding = Finding(
        check_id="http.headers.csp",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        title=f"title{_LONE}",
        description=f"description{_LONE}",
        location=location,
        remediation=f"remediation{_LONE}",
        evidence=(EvidenceItem.of(f"label{_LONE}", f"evidence{_LONE}"),),
        references=(f"https://example.com/ref{_LONE}",),
        fingerprint=compute_fingerprint("http.headers.csp", location, f"key{_LONE}"),
    )
    return make_result(finding, warnings=[f"warning{_LONE}"])


@pytest.mark.parametrize("fmt", _FORMATS)
def test_each_format_writes_a_scan_that_met_the_character_to_a_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fmt: str
) -> None:
    """``--output``: the file is written, is valid UTF-8 and shows the replacement."""

    async def run(_self: Orchestrator, _url: str) -> ScanResult:
        return _hostile_result()

    monkeypatch.setattr(app_mod.Orchestrator, "run", run)
    target = tmp_path / f"report.{fmt}"

    result = runner.invoke(
        app_mod.app, ["scan", "https://example.com", "--format", fmt, "--output", str(target)]
    )

    assert result.exit_code == 0, result.stderr
    text = target.read_bytes().decode("utf-8")
    assert "title" + _REPLACED in text or "title\\ufffd" in text
    with pytest.raises(UnicodeEncodeError):  # positive control: the raw value cannot be written
        f"evidence{_LONE}".encode()


@pytest.mark.parametrize("fmt", _FORMATS)
def test_each_format_prints_a_scan_that_met_the_character_to_stdout(
    monkeypatch: pytest.MonkeyPatch, fmt: str
) -> None:
    """Stdout: the report comes out whole, with the replacement."""

    async def run(_self: Orchestrator, _url: str) -> ScanResult:
        return _hostile_result()

    monkeypatch.setattr(app_mod.Orchestrator, "run", run)

    result = runner.invoke(app_mod.app, ["scan", "https://example.com", "--format", fmt])

    assert result.exit_code == 0, result.stderr
    assert "title" + _REPLACED in result.stdout or "title\\ufffd" in result.stdout


@pytest.mark.parametrize("fmt", _FORMATS)
def test_a_saved_report_with_the_replacement_renders_again(tmp_path: Path, fmt: str) -> None:
    """The JSON a hostile scan produced reloads and renders in every format."""
    path = tmp_path / "scan.json"
    path.write_text(get_reporter("json").render(_hostile_result()), "utf-8")

    reloaded = load_result(path)

    assert reloaded.findings[0].evidence[0].content == f"evidence{_REPLACED}"
    get_reporter(fmt).render(reloaded).encode("utf-8")


@pytest.mark.parametrize("fmt", _FORMATS)
def test_a_report_file_with_an_escaped_surrogate_reads_as_the_replacement(
    tmp_path: Path, fmt: str
) -> None:
    """The file loads equal to its clean twin and renders; pydantic alone refuses it."""
    document = _report_document(findings=1)
    twin = json.loads(json.dumps(document))
    document["findings"][0]["title"] = f"title{_LONE}"
    twin["findings"][0]["title"] = f"title{_REPLACED}"
    path = _write(tmp_path / "scan.json", document)
    assert json.dumps(_LONE)[1:-1] in path.read_text("utf-8")  # the path under test ran
    with pytest.raises(ValidationError):  # positive control: the fast parser alone refuses it
        ScanResult.model_validate_json(path.read_bytes())

    loaded = load_result(path)

    assert loaded == load_result(_write(tmp_path / "twin.json", twin))
    assert loaded.findings[0].title == f"title{_REPLACED}"
    get_reporter(fmt).render(loaded).encode("utf-8")


@pytest.mark.parametrize("fmt", _FORMATS)
def test_an_escaped_surrogate_in_a_field_without_a_size_bound_is_replaced(
    tmp_path: Path, fmt: str
) -> None:
    """The fingerprint has no bounded type: the read itself has to clean it."""
    document = _report_document(findings=1)
    document["findings"][0]["fingerprint"] = f"print{_LONE}"
    path = _write(tmp_path / "scan.json", document)

    loaded = load_result(path)

    assert loaded.findings[0].fingerprint == f"print{_REPLACED}"
    get_reporter(fmt).render(loaded).encode("utf-8")


def test_only_a_file_that_is_not_json_to_pydantic_takes_the_slower_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A valid report and a report with a bad field never reach the second parser."""
    good = _report_document(findings=1)
    bad = json.loads(json.dumps(good))
    bad["findings"][0]["severity"] = "VALUE-FROM-THE-FILE"
    escaped = json.loads(json.dumps(good))
    escaped["findings"][0]["title"] = f"title{_LONE}"
    calls: list[object] = []
    real = json.loads
    monkeypatch.setattr(json, "loads", lambda *a: calls.append(a) or real(*a))

    load_result(_write(tmp_path / "good.json", good))
    with pytest.raises(ValueError, match="1 error"):
        load_result(_write(tmp_path / "bad.json", bad))
    assert calls == []

    load_result(_write(tmp_path / "escaped.json", escaped))  # positive control: this one does
    assert len(calls) == 1


def test_the_slower_read_still_refuses_what_is_not_a_report(tmp_path: Path) -> None:
    """A document that needs it and is not a report gets the same bounded message."""
    document = _report_document(findings=1)
    document["findings"][0]["title"] = f"title{_LONE}"
    document["findings"][0]["severity"] = "VALUE-FROM-THE-FILE"
    path = _write(tmp_path / "scan.json", document)

    with pytest.raises(ValueError) as caught:
        load_result(path)

    assert str(caught.value) == "not a valid WebVigil report: 1 error, at findings[0].severity"


async def test_a_real_scan_of_such_a_page_writes_every_format(
    httpx_mock: HttpxMock,
) -> None:
    """From the transport to the report: the page's text reaches a finding and every writer."""
    form = f'<form method="post" action="/send{_LONE}"><input name="note"></form>'
    body = _encoded(f"<html><body>{form}</body></html>")
    pages = {"/": (body, f"text/html; charset={_FIXTURE_ENCODING}")}

    result = await _scan(httpx_mock, pages)

    quoted = [
        finding.location.url
        for finding in result.findings
        if finding.check_id == "csrf.form.no-token"
    ]
    assert quoted == [f"{_BASE}send{_REPLACED}"]  # the page's text got this far
    for fmt in _FORMATS:
        get_reporter(fmt).render(result).encode("utf-8")


@pytest.mark.parametrize("field", ["technologies", "errors", "warnings", "findings"])
def test_validation_stops_at_the_first_bad_item_of_a_report_list(
    tmp_path: Path, field: str
) -> None:
    """A small file cannot make the validator keep one error for each of its items."""
    document = _report_document()
    document[field] = [12345] * 1000
    path = _write(tmp_path / "scan.json", document)

    with pytest.raises(ValidationError) as raw:
        ScanResult.model_validate_json(path.read_bytes())

    assert raw.value.error_count() == 1
    assert raw.value.errors()[0]["loc"][:2] == (field, 0)


@pytest.mark.parametrize("field", ["evidence", "cwe", "references"])
def test_validation_stops_at_the_first_bad_item_of_a_finding_list(
    tmp_path: Path, field: str
) -> None:
    """The lists inside a finding are bounded the same way."""
    document = _report_document(findings=1)
    document["findings"][0][field] = [None] * 1000
    path = _write(tmp_path / "scan.json", document)

    with pytest.raises(ValidationError) as raw:
        ScanResult.model_validate_json(path.read_bytes())

    assert raw.value.error_count() == 1
    assert raw.value.errors()[0]["loc"][:4] == ("findings", 0, field, 0)


def test_a_report_with_too_many_severity_counts_is_one_error(tmp_path: Path) -> None:
    """The counts are a mapping, which has no first-error mode, so its size is checked first."""
    document = _report_document()
    document["metadata"]["counts"] = {str(n): "not-a-number" for n in range(1000)}
    path = _write(tmp_path / "scan.json", document)

    with pytest.raises(ValidationError) as raw:
        ScanResult.model_validate_json(path.read_bytes())

    assert raw.value.error_count() == 1
    assert raw.value.errors()[0]["loc"] == ("metadata", "counts")


def test_validation_stops_at_the_first_bad_advisory_of_a_technology() -> None:
    """The one list a technology holds is bounded like the others."""
    with pytest.raises(ValidationError) as raw:
        Technology.model_validate(
            {
                "name": "library",
                "version": None,
                "detection": next(iter(DetectionMethod)),
                "source_url": "https://example.com/",
                "advisories": [None] * 1000,
            }
        )

    assert raw.value.error_count() == 1
    assert raw.value.errors()[0]["loc"] == ("advisories", 0)
