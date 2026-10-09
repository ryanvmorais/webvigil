"""
HAR import — spec 021 RF-01 to RF-11, RNF-02, RNF-03, RNF-05.

Every case builds a HAR document as a dict, writes it under ``tmp_path`` and loads it through
:func:`load_har`; nothing touches the network (the importer opens no socket) and nothing is mocked
except the module's size and entry caps, which are lowered with ``monkeypatch`` so a bound can be
shown without a 64 MiB file. The target is always ``https://shop.example.com``. The shapes of the
six tools of RF-02 are small hand-trimmed documents that differ the way the tools do (resource
type, mime type, ``params`` against ``text``), not captures of real traffic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from webvigil.core.errors import HarError
from webvigil.core.target import Scope, Target
from webvigil.crawler import har
from webvigil.crawler.har import HarImport, load_har, merge_operations
from webvigil.crawler.openapi import ApiOperation

_TARGET = Target.parse("https://shop.example.com")
_SITE = "https://shop.example.com"


def _entry(
    url: str,
    method: str = "GET",
    *,
    rtype: str | None = None,
    mime: str | None = None,
    headers: list[dict[str, str]] | None = None,
    cookies: list[dict[str, str]] | None = None,
    post: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Args:
        url (str): The request URL.
        method (str): The request method. Defaults to ``"GET"``.
        rtype (str | None): Chrome's ``_resourceType``, when the tool writes one.
        mime (str | None): The response ``content.mimeType``, when the tool writes one.
        headers (list[dict[str, str]] | None): Request headers as ``{"name", "value"}``.
        cookies (list[dict[str, str]] | None): Request cookies.
        post (dict[str, Any] | None): The ``postData`` object.

    Returns:
        dict[str, Any]: A HAR entry.
    """
    request: dict[str, Any] = {"method": method, "url": url, "headers": headers or []}
    if cookies is not None:
        request["cookies"] = cookies
    if post is not None:
        request["postData"] = post
    entry: dict[str, Any] = {"request": request, "response": {"status": 200, "content": {}}}
    if mime is not None:
        entry["response"]["content"]["mimeType"] = mime
    if rtype is not None:
        entry["_resourceType"] = rtype
    return entry


def _load(
    tmp_path: Path,
    entries: list[Any],
    *,
    target: Target = _TARGET,
    max_operations: int = 150,
) -> HarImport:
    """
    Args:
        tmp_path (Path): The pytest temp directory.
        entries (list[Any]): The ``log.entries`` of the document.
        target (Target): The scan target. Defaults to the shop.
        max_operations (int): The operation cap. Defaults to 150.

    Returns:
        HarImport: The loaded file.
    """
    path = tmp_path / "traffic.har"
    path.write_text(json.dumps({"log": {"version": "1.2", "entries": entries}}), "utf-8")
    return load_har(str(path), target=target, max_operations=max_operations)


def _shape(op: ApiOperation) -> tuple[str, str, tuple[tuple[str, str], ...]]:
    """
    Args:
        op (ApiOperation): An operation.

    Returns:
        tuple[str, str, tuple[tuple[str, str], ...]]: Its method, URL and the fields it carries.
    """
    return op.method, op.url, op.query or op.body_fields


# ---------------------------------------------------------------------------
# The six tools of RF-02
# ---------------------------------------------------------------------------

_FORM = "application/x-www-form-urlencoded"

# (rtype, js mime, form post) per tool: how each one records the same walk
_TOOLS = {
    "chrome": ("xhr", "application/json", {"mimeType": _FORM, "text": "comment=hi", "params": []}),
    "firefox": (
        None,
        "application/json",
        {"mimeType": _FORM, "params": [{"name": "comment", "value": "hi"}]},
    ),
    "safari": (None, "application/json", {"mimeType": _FORM, "text": "comment=hi"}),
    "burp": (None, None, {"mimeType": _FORM, "text": "comment=hi"}),
    "zap": (None, "application/json;charset=utf-8", {"mimeType": _FORM, "text": "comment=hi"}),
    "mitmproxy": (
        None,
        "application/json",
        {"mimeType": _FORM, "text": "comment=hi", "params": []},
    ),
}


@pytest.mark.parametrize("tool", sorted(_TOOLS))
def test_each_tool_shape_loads_to_the_same_operations(tmp_path: Path, tool: str) -> None:
    """A search GET and a form POST come out identical however the tool wrote them."""
    rtype, mime, post = _TOOLS[tool]
    result = _load(
        tmp_path,
        [
            _entry(f"{_SITE}/rest/products/search?q=apple", rtype=rtype, mime=mime),
            _entry(f"{_SITE}/rest/feedback", "POST", rtype=rtype, mime=mime, post=post),
            _entry(f"{_SITE}/main.js", rtype="script" if rtype else None, mime=None),
        ],
    )
    assert [_shape(op) for op in result.operations] == [
        ("POST", f"{_SITE}/rest/feedback", (("comment", "hi"),)),
        ("GET", f"{_SITE}/rest/products/search", (("q", "apple"),)),
    ]
    assert {op.source for op in result.operations} == {"har"}
    assert result.tally.static == 1


# ---------------------------------------------------------------------------
# What an entry is: scope, method, static, unsafe, malformed (RF-02 to RF-04, RF-09)
# ---------------------------------------------------------------------------

_BAD_ENTRIES = [
    pytest.param(_entry("https://cdn.example.net/lib"), "out_of_scope", id="other-host"),
    pytest.param(_entry("http://shop.example.com/x"), "out_of_scope", id="other-scheme"),
    pytest.param(_entry("wss://shop.example.com/socket"), "out_of_scope", id="websocket"),
    pytest.param(_entry("data:image/png;base64,AAAA"), "out_of_scope", id="data-url"),
    pytest.param(_entry("chrome-extension://abc/x"), "out_of_scope", id="extension"),
    pytest.param(_entry(f"{_SITE}/rest/a", "OPTIONS"), "other_method", id="options"),
    pytest.param(_entry(f"{_SITE}/rest/a/1", "DELETE"), "other_method", id="delete"),
    pytest.param(_entry(f"{_SITE}/rest/a/1", "put"), "other_method", id="put"),
    pytest.param(_entry(f"{_SITE}/x", rtype="script"), "static", id="resource-type"),
    pytest.param(_entry(f"{_SITE}/x", mime="image/png"), "static", id="mime-image"),
    pytest.param(_entry(f"{_SITE}/x", mime="text/css; charset=utf-8"), "static", id="mime-css"),
    pytest.param(_entry(f"{_SITE}/assets/app.woff2"), "static", id="extension"),
    pytest.param(_entry(f"{_SITE}/app.js.map", mime="application/json"), "static", id="map"),
    pytest.param(_entry(f"{_SITE}/rest/user/login", "POST"), "unsafe", id="login"),
    pytest.param(_entry(f"{_SITE}/api/account/delete_item"), "unsafe", id="delete-path"),
    pytest.param(_entry(f"{_SITE}/api/change-password", "POST"), "unsafe", id="password"),
    pytest.param(_entry(f"{_SITE}/rest/checkout"), "unsafe", id="checkout"),
    pytest.param("not an entry", "malformed", id="not-a-dict"),
    pytest.param({"response": {}}, "malformed", id="no-request"),
    pytest.param({"request": {"method": "GET", "url": 3}}, "malformed", id="url-not-a-string"),
    pytest.param({"request": {"url": f"{_SITE}/a"}}, "malformed", id="no-method"),
    pytest.param(_entry(f"{_SITE}/a?{'n' * 129}=1"), "malformed", id="name-too-long"),
    pytest.param(_entry(f"{_SITE}/{'a' * 2100}"), "malformed", id="url-too-long"),
    pytest.param(_entry(f"{_SITE}:99999/a"), "malformed", id="bad-port"),
]


@pytest.mark.parametrize(("entry", "reason"), _BAD_ENTRIES)
def test_an_entry_that_fails_a_rule_is_counted_and_not_imported(
    tmp_path: Path, entry: Any, reason: str
) -> None:
    """Each filter leaves no operation and bumps its own tally and no other."""
    result = _load(tmp_path, [entry])
    counts = {
        name: getattr(result.tally, name)
        for name in ("out_of_scope", "static", "other_method", "unsafe", "malformed")
    }
    assert counts == {name: int(name == reason) for name in counts}
    assert result.operations == []


def test_a_dynamic_resource_type_wins_over_a_script_extension(tmp_path: Path) -> None:
    """An ``xhr`` to a ``.js`` URL is an API call, not an asset."""
    result = _load(tmp_path, [_entry(f"{_SITE}/api/config.js?v=1", rtype="xhr")])
    assert [op.url for op in result.operations] == [f"{_SITE}/api/config.js"]


def test_a_foreign_options_preflight_is_out_of_scope_not_another_method(tmp_path: Path) -> None:
    """The scope step runs first, so 'other method' counts only the target's own entries."""
    result = _load(tmp_path, [_entry("https://cdn.example.net/x", "OPTIONS")])
    assert (result.tally.out_of_scope, result.tally.other_method) == (1, 0)


def test_scope_subdomains_accepts_a_sibling_host_and_host_does_not(tmp_path: Path) -> None:
    """``--scope subdomains`` takes a sibling subdomain; ``host`` refuses it."""
    entries = [_entry("https://api.example.com/rest/items?id=1")]
    wide = Target.parse("https://shop.example.com", scope=Scope.SUBDOMAINS)
    assert len(_load(tmp_path, entries, target=wide).operations) == 1
    assert _load(tmp_path, entries).operations == []


# ---------------------------------------------------------------------------
# Building an operation (RF-05, RF-06)
# ---------------------------------------------------------------------------


def test_the_url_loses_its_userinfo_and_fragment_and_keeps_a_custom_port(tmp_path: Path) -> None:
    """Credentials in a URL never become an operation, and an odd port is kept as recorded."""
    wide = Target.parse("https://shop.example.com", scope=Scope.SUBDOMAINS)
    result = _load(
        tmp_path,
        [
            _entry("https://user:pw@shop.example.com/a?x=1#frag"),
            _entry("https://api.example.com:8443/b?y=2"),
            _entry("https://shop.example.com:443/c?z=3"),
        ],
        target=wide,
    )
    assert [op.url for op in result.operations] == [
        "https://api.example.com:8443/b",
        f"{_SITE}/a",
        f"{_SITE}/c",
    ]
    assert "pw" not in repr(result)


def test_the_query_keeps_its_order_blank_values_and_repeats(tmp_path: Path) -> None:
    """A query is imported as recorded: in order, with a blank value and a repeated name."""
    result = _load(tmp_path, [_entry(f"{_SITE}/rest/s?b=2&a=&b=3&c=x%20y")])
    assert result.operations[0].query == (("b", "2"), ("a", ""), ("b", "3"), ("c", "x y"))
    assert result.operations[0].seed_url == f"{_SITE}/rest/s?b=2&a=&b=3&c=x+y"


def test_a_form_body_comes_from_params_or_text_and_a_get_has_none(tmp_path: Path) -> None:
    """``params`` and ``text`` give the same fields; a GET never reads ``postData``."""
    from_params = {"mimeType": _FORM, "params": [{"name": "a", "value": "1"}]}
    from_text = {"mimeType": _FORM, "text": "a=1&b=2"}
    result = _load(
        tmp_path,
        [
            _entry(f"{_SITE}/p1", "POST", post=from_params),
            _entry(f"{_SITE}/p2", "POST", post=from_text),
            _entry(f"{_SITE}/g", "GET", post=from_text),
        ],
    )
    by_url = {op.url: op for op in result.operations}
    assert by_url[f"{_SITE}/p1"].body_fields == (("a", "1"),)
    assert by_url[f"{_SITE}/p2"].body_fields == (("a", "1"), ("b", "2"))
    assert by_url[f"{_SITE}/g"].body_fields == ()


def test_multipart_text_parts_are_fields_and_file_parts_are_not(tmp_path: Path) -> None:
    """Both the Firefox ``params`` form and the raw-text form drop a part that has a file."""
    raw = "\r\n".join(
        [
            "--XX",
            'Content-Disposition: form-data; name="title"',
            "",
            "hello",
            "--XX",
            'Content-Disposition: form-data; name="upload"; filename="a.png"',
            "Content-Type: image/png",
            "",
            "PNGDATA",
            "--XX--",
            "",
        ]
    )
    params = [{"name": "title", "value": "hello"}, {"name": "upload", "fileName": "a.png"}]
    mime = "multipart/form-data; boundary=XX"
    result = _load(
        tmp_path,
        [
            _entry(f"{_SITE}/m1", "POST", post={"mimeType": mime, "params": params}),
            _entry(f"{_SITE}/m2", "POST", post={"mimeType": mime, "text": raw}),
        ],
    )
    assert [op.body_fields for op in result.operations] == [(("title", "hello"),)] * 2


def test_a_body_of_another_type_keeps_the_route_with_no_body(tmp_path: Path) -> None:
    """An XML or empty ``POST`` is still a route; there is just no body to import."""
    result = _load(
        tmp_path,
        [
            _entry(f"{_SITE}/x", "POST", post={"mimeType": "text/xml", "text": "<a/>"}),
            _entry(f"{_SITE}/y", "POST"),
        ],
    )
    assert [(op.body_fields, op.body_json) for op in result.operations] == [((), None)] * 2


_SHAPES = [
    (
        '{"a": "secret", "n": 5, "f": 1.5, "b": false, "z": null}',
        '{"a": "wv", "n": 1, "f": 1, "b": true, "z": null}',
    ),
    ('{"items": [{"id": 7}, {"id": 8}]}', '{"items": [{"id": 1}]}'),
    ('{"items": []}', '{"items": []}'),
    ("[1, 2]", "[1]"),
    ('{"a": {"b": {"c": {"d": {"e": 1}}}}}', '{"a": {"b": {"c": {"d": {}}}}}'),
    ('{"query": "{ users { id } }", "variables": {}}', '{"query": "wv", "variables": {}}'),
]


@pytest.mark.parametrize(("body", "expected"), _SHAPES)
def test_a_json_body_is_imported_as_its_shape(tmp_path: Path, body: str, expected: str) -> None:
    """Structure survives; every leaf is a typed placeholder, so no recorded value does."""
    post = {"mimeType": "application/json; charset=utf-8", "text": body}
    result = _load(tmp_path, [_entry(f"{_SITE}/api/j", "POST", post=post)])
    assert result.operations[0].body_json == expected


@pytest.mark.parametrize(
    "body",
    ["{not json", "null", "42", '"text"', "[" * 50_000],
    ids=["invalid", "null", "number", "string", "too-deep"],
)
def test_a_json_body_that_is_not_an_object_or_array_keeps_the_route_only(
    tmp_path: Path, body: str
) -> None:
    """Invalid, scalar and absurdly nested JSON give no body and no error."""
    post = {"mimeType": "application/json", "text": body}
    result = _load(tmp_path, [_entry(f"{_SITE}/api/j", "POST", post=post)])
    assert [op.body_json for op in result.operations] == [None]


def test_a_wide_json_body_keeps_only_its_first_keys(tmp_path: Path) -> None:
    """The breadth bound of the shape is the OpenAPI synthesis one (24 keys)."""
    body = json.dumps({f"k{i}": i for i in range(60)})
    post = {"mimeType": "application/json", "text": body}
    result = _load(tmp_path, [_entry(f"{_SITE}/api/j", "POST", post=post)])
    assert len(json.loads(result.operations[0].body_json or "")) == 24


# ---------------------------------------------------------------------------
# Secrets (RF-07, RF-08, RNF-05)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["token", "access_token", "accessToken", "API-Key", "api_key", "apikey", "secret", "password",
     "passwd", "pwd", "auth", "Authorization", "session", "sid", "jwt", "signature",
     "otp", "csrf", "_csrf", "xsrf-token", "tokens", "credential", "bearer"],
)  # fmt: skip
def test_a_secret_looking_name_gets_a_placeholder_value(tmp_path: Path, name: str) -> None:
    """The name is kept (it is still an injection point); its value is not."""
    result = _load(tmp_path, [_entry(f"{_SITE}/rest/s?{name}=LEAKME")])
    assert result.operations[0].query == ((name, "wv"),)


@pytest.mark.parametrize("name", ["q", "limit", "tokenizer", "monkey", "author", "status", "page"])
def test_an_ordinary_name_keeps_its_recorded_value(tmp_path: Path, name: str) -> None:
    """Word matching does not catch ``tokenizer``, ``monkey`` or ``author``."""
    result = _load(tmp_path, [_entry(f"{_SITE}/rest/s?{name}=apple")])
    assert result.operations[0].query == ((name, "apple"),)


def test_a_value_over_the_bound_becomes_a_placeholder(tmp_path: Path) -> None:
    """A blob is not a baseline: 256 characters stay, 257 do not."""
    result = _load(tmp_path, [_entry(f"{_SITE}/rest/s?a={'x' * 256}&b={'y' * 257}")])
    assert result.operations[0].query == (("a", "x" * 256), ("b", "wv"))


def test_a_secret_named_form_field_is_scrubbed_too(tmp_path: Path) -> None:
    """The rule is for form bodies as well as queries."""
    post = {"mimeType": _FORM, "text": "note=hi&api_key=LEAKME"}
    result = _load(tmp_path, [_entry(f"{_SITE}/rest/n", "POST", post=post)])
    assert result.operations[0].body_fields == (("note", "hi"), ("api_key", "wv"))


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"headers": [{"name": "Cookie", "value": "s=1"}]}, True),
        ({"headers": [{"name": "authorization", "value": "Bearer x"}]}, True),
        ({"cookies": [{"name": "s", "value": "1"}]}, True),
        ({"headers": [{"name": "Accept", "value": "*/*"}], "cookies": []}, False),
        ({}, False),
    ],
)
def test_authenticated_is_set_by_session_header_names_or_cookies(
    tmp_path: Path, kwargs: dict[str, Any], expected: bool
) -> None:
    """A ``Cookie`` or ``Authorization`` header, or recorded cookies, mark the recording."""
    assert _load(tmp_path, [_entry(f"{_SITE}/rest/a", **kwargs)]).authenticated is expected


def test_a_foreign_entrys_cookie_does_not_make_the_recording_authenticated(tmp_path: Path) -> None:
    """Only the target's own entries count: a tracker's cookie is not a session."""
    foreign = _entry("https://tracker.example.net/p", headers=[{"name": "Cookie", "value": "t=1"}])
    assert _load(tmp_path, [foreign]).authenticated is False


def test_nothing_secret_in_a_recording_survives_into_the_result(tmp_path: Path) -> None:
    """An adversarial file: no cookie, bearer, key, query token or password is in the result."""
    secrets = ["SESSIONCOOKIE9", "eyJBEARER9", "APIKEYVALUE9", "URLTOKEN9", "hunter2PASSWORD9"]
    entry = _entry(
        f"{_SITE}/rest/profile?token=URLTOKEN9&sid=URLTOKEN9&tab=main",
        "POST",
        headers=[
            {"name": "Cookie", "value": "connect.sid=SESSIONCOOKIE9"},
            {"name": "Authorization", "value": "Bearer eyJBEARER9"},
            {"name": "X-Api-Key", "value": "APIKEYVALUE9"},
        ],
        cookies=[{"name": "connect.sid", "value": "SESSIONCOOKIE9"}],
        post={"mimeType": _FORM, "text": "pwd=hunter2PASSWORD9&bio=hi"},
    )
    entry["response"]["headers"] = [{"name": "Set-Cookie", "value": "x=SESSIONCOOKIE9"}]
    entry["response"]["content"]["text"] = "eyJBEARER9 APIKEYVALUE9"
    result = _load(tmp_path, [entry])
    assert result.authenticated is True
    rendered = repr(result) + result.summary()
    assert [s for s in secrets if s in rendered] == []
    assert result.operations[0].query == (("token", "wv"), ("sid", "wv"), ("tab", "main"))
    assert result.operations[0].body_fields == (("pwd", "wv"), ("bio", "hi"))


# ---------------------------------------------------------------------------
# Identity, order, caps and the summary (RF-05, RF-11, RNF-02, RNF-03)
# ---------------------------------------------------------------------------


def test_the_same_route_recorded_twice_is_one_operation_with_the_first_values(
    tmp_path: Path,
) -> None:
    """Values are not part of the identity; names are."""
    result = _load(
        tmp_path,
        [
            _entry(f"{_SITE}/rest/s?q=first"),
            _entry(f"{_SITE}/rest/s?q=second"),
            _entry(f"{_SITE}/rest/s?q=third&page=2"),
        ],
    )
    assert [op.query for op in result.operations] == [
        (("q", "first"),),
        (("q", "third"), ("page", "2")),
    ]
    assert result.tally.duplicate == 1


def test_the_order_is_stable_and_independent_of_the_recording_order(tmp_path: Path) -> None:
    """The same entries in any order give the same operations and summary."""
    entries = [_entry(f"{_SITE}/rest/{name}?a=1") for name in ("zeta", "alpha", "mid")]
    first = _load(tmp_path, entries)
    second = _load(tmp_path, list(reversed(entries)))
    assert [op.url for op in first.operations] == [
        f"{_SITE}/rest/{n}" for n in ("alpha", "mid", "zeta")
    ]
    assert first.operations == second.operations
    assert first.summary() == second.summary()


def test_the_operation_cap_keeps_the_first_in_order_and_warns(tmp_path: Path) -> None:
    """``max_operations`` cuts the stable list and says how many were dropped."""
    result = _load(tmp_path, [_entry(f"{_SITE}/rest/{n}") for n in "cab"], max_operations=2)
    assert [op.url for op in result.operations] == [f"{_SITE}/rest/a", f"{_SITE}/rest/b"]
    assert result.warnings == ["HAR import seeded the first 2 of 3 operations"]


def test_entries_past_the_entry_cap_are_ignored_with_a_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A recording longer than the entry cap is read only that far."""
    monkeypatch.setattr(har, "_MAX_ENTRIES", 2)
    result = _load(tmp_path, [_entry(f"{_SITE}/rest/{n}") for n in "abcd"])
    assert result.tally.entries == 2
    assert result.warnings == ["HAR import read the first 2 of 4 entries"]


def test_a_recording_with_nothing_usable_warns_and_is_not_an_error(tmp_path: Path) -> None:
    """All entries filtered out: the scan continues with a warning."""
    result = _load(tmp_path, [_entry("https://cdn.example.net/x")])
    assert result.operations == []
    assert result.warnings == ["HAR file contained no usable in-scope GET or POST operations"]


def test_the_summary_line_names_the_counts_and_leaves_zeroes_out(tmp_path: Path) -> None:
    """RF-11: one line that tells 'no finding' from 'never imported'."""
    result = _load(
        tmp_path,
        [
            _entry(f"{_SITE}/rest/a?q=1"),
            _entry(f"{_SITE}/rest/b", "POST", post={"mimeType": _FORM, "text": "x=1"}),
            _entry("https://cdn.example.net/x"),
            _entry("https://cdn.example.net/y"),
            _entry(f"{_SITE}/s.js", rtype="script"),
            _entry(f"{_SITE}/rest/c", "PATCH"),
            _entry(f"{_SITE}/rest/user/login", "POST"),
            "junk",
        ],
    )
    assert result.summary() == (
        "HAR import: 8 entries read, 2 operations seeded (1 GET, 1 POST); ignored: "
        "2 out of scope, 1 static, 1 other method, 1 unsafe, 1 malformed"
    )
    assert _load(tmp_path, [_entry(f"{_SITE}/rest/a")]).summary() == (
        "HAR import: 1 entry read, 1 operation seeded (1 GET, 0 POST)"
    )


# ---------------------------------------------------------------------------
# The file (RF-01, RF-02, RNF-02)
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, content: bytes) -> str:
    """
    Args:
        tmp_path (Path): The pytest temp directory.
        content (bytes): The file's bytes.

    Returns:
        str: The path of the written file.
    """
    path = tmp_path / "x.har"
    path.write_bytes(content)
    return str(path)


def test_a_utf8_byte_order_mark_is_tolerated(tmp_path: Path) -> None:
    """Some exporters write a BOM; the file still loads."""
    doc = {"log": {"entries": [_entry(f"{_SITE}/rest/a?q=1")]}}
    path = _write(tmp_path, b"\xef\xbb\xbf" + json.dumps(doc).encode())
    assert len(load_har(path, target=_TARGET, max_operations=150).operations) == 1


@pytest.mark.parametrize(
    "content",
    [
        b"{not json",
        b"\xff\xfe\x00",
        b"[]",
        b'{"log": {}}',
        b'{"log": {"entries": "x"}}',
        b"[" * 100_000,
    ],
    ids=[
        "invalid-json",
        "not-utf8",
        "not-an-object",
        "no-entries",
        "entries-not-a-list",
        "too-deep",
    ],
)
def test_a_file_that_is_not_a_har_is_a_har_error(tmp_path: Path, content: bytes) -> None:
    """Bad JSON, a wrong shape and a nesting bomb are fatal, not crashes."""
    with pytest.raises(HarError, match="not a HAR file"):
        load_har(_write(tmp_path, content), target=_TARGET, max_operations=150)


def test_a_url_source_is_a_har_error(tmp_path: Path) -> None:
    """``--har`` takes a local file; a URL is refused before anything is read."""
    with pytest.raises(HarError, match="local file"):
        load_har("https://shop.example.com/traffic.har", target=_TARGET, max_operations=1)


def test_a_missing_path_is_a_har_error(tmp_path: Path) -> None:
    """A path that does not exist names itself in the error."""
    with pytest.raises(HarError, match=r"missing\.har"):
        load_har(str(tmp_path / "missing.har"), target=_TARGET, max_operations=1)


def test_a_directory_is_a_har_error(tmp_path: Path) -> None:
    """A directory is not a file."""
    with pytest.raises(HarError, match="not found"):
        load_har(str(tmp_path), target=_TARGET, max_operations=1)


def test_a_file_over_the_size_cap_is_refused_before_it_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cap is checked on ``stat``; the error names the fix."""
    monkeypatch.setattr(har, "_MAX_FILE_BYTES", 10)
    path = _write(tmp_path, b"x" * 11)  # not JSON: reading it would be a different error
    with pytest.raises(HarError, match="without response bodies"):
        load_har(path, target=_TARGET, max_operations=1)


# ---------------------------------------------------------------------------
# Merging with an OpenAPI import (RF-01)
# ---------------------------------------------------------------------------


def _op(url: str, source: str, query: tuple[tuple[str, str], ...] = ()) -> ApiOperation:
    """
    Args:
        url (str): The operation URL (also its template).
        source (str): ``"openapi"`` or ``"har"``.
        query (tuple[tuple[str, str], ...]): Its query.

    Returns:
        ApiOperation: A GET operation.
    """
    return ApiOperation("GET", url, url, query, (), (), None, "", source=source)


def test_merge_keeps_the_primary_on_a_tie_and_appends_the_rest() -> None:
    """An operation with the same method, URL and parameter names is the primary's."""
    api = [_op(f"{_SITE}/a", "openapi", (("q", "wv"),))]
    recorded = [
        _op(f"{_SITE}/a", "har", (("q", "apple"),)),
        _op(f"{_SITE}/a", "har", (("q", "x"), ("p", "1"))),
        _op(f"{_SITE}/b", "har"),
    ]
    merged = merge_operations(api, recorded)
    assert [(op.url, op.source, op.query) for op in merged] == [
        (f"{_SITE}/a", "openapi", (("q", "wv"),)),
        (f"{_SITE}/a", "har", (("q", "x"), ("p", "1"))),
        (f"{_SITE}/b", "har", ()),
    ]
    assert merge_operations([], []) == []


# ---------------------------------------------------------------------------
# Bounds on one entry (RNF-02)
# ---------------------------------------------------------------------------


def test_a_query_or_form_with_too_many_parameters_is_malformed(tmp_path: Path) -> None:
    """More than 100 parameters is not a request worth replaying; the entry is skipped."""
    many = "&".join(f"p{i}=1" for i in range(101))
    post = {"mimeType": _FORM, "text": many}
    result = _load(tmp_path, [_entry(f"{_SITE}/a?{many}"), _entry(f"{_SITE}/b", "POST", post=post)])
    assert (result.operations, result.tally.malformed) == ([], 2)


def test_a_multipart_body_with_no_boundary_has_no_fields(tmp_path: Path) -> None:
    """Without a boundary in the mime type the raw text cannot be split; the route stays."""
    post = {"mimeType": "multipart/form-data", "text": "--XX\r\nanything"}
    result = _load(tmp_path, [_entry(f"{_SITE}/m", "POST", post=post)])
    assert [op.body_fields for op in result.operations] == [()]


def test_a_json_key_longer_than_the_name_bound_is_left_out_of_the_shape(tmp_path: Path) -> None:
    """A key is a name like any other: over 128 characters it is dropped."""
    post = {"mimeType": "application/json", "text": json.dumps({"k" * 129: 1, "ok": 1})}
    result = _load(tmp_path, [_entry(f"{_SITE}/j", "POST", post=post)])
    assert result.operations[0].body_json == '{"ok": 1}'


def test_a_file_that_cannot_be_read_is_a_har_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An operating-system error while reading is reported, not raised raw."""

    def _deny(self: Path) -> bytes:
        raise PermissionError("denied")

    path = _write(tmp_path, b"{}")
    monkeypatch.setattr(Path, "read_bytes", _deny)
    with pytest.raises(HarError, match="could not read"):
        load_har(path, target=_TARGET, max_operations=1)
