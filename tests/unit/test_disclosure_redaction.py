"""
Secret redaction for probe evidence — RNF-06, ADR-9.

The point of every case: after redaction the caller can still tell *what kind of
thing* leaked (the keys, the JSON structure) but not *the secret itself*, and
the output is always length-bounded.
"""

from __future__ import annotations

import json
import tracemalloc

import pytest

from webvigil.checks.disclosure import redaction

_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
_HEX40 = "a" * 45
_PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc123\n-----END RSA PRIVATE KEY-----"


def test_dotenv_keeps_keys_and_masks_values() -> None:
    """The ``dotenv`` strategy keeps every ``KEY``, comments and all, but masks the values."""
    body = f"# comment\nexport AWS_ACCESS_KEY_ID={_AWS_KEY}\nDB_PASSWORD=hunter2\nEMPTY=\n"
    out = redaction.apply("dotenv", body)
    assert "AWS_ACCESS_KEY_ID" in out
    assert "DB_PASSWORD" in out
    assert _AWS_KEY not in out
    assert "hunter2" not in out
    assert "# comment" in out


def test_json_env_keeps_names_and_masks_values() -> None:
    """The ``json-env`` strategy keeps the JSON structure and key names but scrubs secret values."""
    body = json.dumps(
        {
            "activeProfiles": ["prod"],
            "propertySources": [
                {"name": "systemEnvironment", "properties": {"DB_PW": {"value": "s3cr3t"}}}
            ],
        }
    )
    out = redaction.apply("json-env", body)
    assert "propertySources" in out
    assert "systemEnvironment" in out
    assert "s3cr3t" not in out


def test_generic_masks_known_secret_shapes() -> None:
    """The ``generic`` strategy masks AWS keys, long hex strings and PEM private-key blocks."""
    body = f"key={_AWS_KEY} hash={_HEX40}\n{_PEM}"
    out = redaction.apply("generic", body)
    assert _AWS_KEY not in out
    assert _HEX40 not in out
    assert "PRIVATE KEY" not in out or "BEGIN RSA PRIVATE KEY" not in out


def test_every_strategy_is_length_bounded() -> None:
    """No strategy, an unknown name included, ever returns more than the cap."""
    big = "SECRET_KEY=" + "x" * 20000 + "\n"
    for strategy in (*redaction.STRATEGIES, "unknown"):
        assert len(redaction.apply(strategy, big)) <= 2000


def test_an_unknown_strategy_gets_the_generic_masking() -> None:
    """A name outside ``STRATEGIES`` masks like ``generic``: no entry goes out unmasked."""
    body = f"line1\nline2 {_AWS_KEY}\n" + "z" * 5000
    out = redaction.apply("none", body)
    assert out == redaction.apply("generic", body)
    assert out.startswith("line1")
    assert _AWS_KEY not in out
    assert len(out) <= 1024


def test_dotenv_drops_every_line_of_a_quoted_value_that_spans_lines() -> None:
    body = f'PRIVATE_KEY="{_PEM}"\nNEXT=1\nAFTER=2'
    out = redaction.apply("dotenv", body)
    assert "MIIabc123" not in out
    assert "PRIVATE KEY-----" not in out
    assert out == "PRIVATE_KEY=***\nNEXT=***\nAFTER=***"


def test_dotenv_masks_a_token_in_a_line_that_is_not_an_assignment() -> None:
    out = redaction.apply("dotenv", f"# old key {_AWS_KEY}\nA=1")
    assert _AWS_KEY not in out
    assert out.startswith("# old key ")


@pytest.mark.parametrize(
    ("body", "secret"),
    [
        pytest.param('<add key="DbPassword" value="hunter2" />', "hunter2", id="web-config"),
        pytest.param(
            'connectionString="Server=db;User Id=app;Password=hunter2;"', "hunter2", id="conn"
        ),
        pytest.param("SECRET_KEY = 'short-one'", "short-one", id="django"),
        pytest.param("'PASSWORD': 'two words'", "two words", id="python-dict"),
        pytest.param("define('DB_PASSWORD', 'hunter2');", "hunter2", id="php-define"),
        pytest.param('$db_pass = "hunter2";', "hunter2", id="php-variable"),
        pytest.param("'db_password' => 'hunter2',", "hunter2", id="php-array"),
        pytest.param("//registry.example/:_authToken=npm_abc123", "npm_abc123", id="npmrc"),
        pytest.param("url=https://example.test/?password=abc123", "abc123", id="nested"),
        pytest.param("url = https://bob:tok3n@git.example/x.git", "tok3n", id="userinfo"),
    ],
)
def test_generic_masks_a_short_secret_by_the_name_it_is_assigned_to(body: str, secret: str) -> None:
    out = redaction.apply("generic", f"DEBUG = True\n{body}")
    assert secret not in out
    # positive control: an assignment to a plain name stays readable
    assert out.startswith("DEBUG = True\n")


def test_generic_hides_the_whole_user_information_of_a_url() -> None:
    out = redaction.apply("generic", "remote = https://bob:tok3n@git.example/x.git")
    assert out == "remote = https://***@git.example/x.git"


def test_json_env_masks_a_secret_by_any_spelling_of_its_name() -> None:
    body = json.dumps(
        {
            "DB_PASSWORD": "short1",
            "jwtSecret": "short2",
            "ConnectionStrings": {"Default": "Server=x;Password=short3"},
            "app": {"name": "shop"},
        }
    )
    out = redaction.apply("json-env", body)
    for secret in ("short1", "short2", "short3"):
        assert secret not in out
    # positive control: a value under a plain name stays readable
    assert '"shop"' in out


@pytest.mark.parametrize("strategy", ["dotenv", "htpasswd"])
def test_a_line_strategy_reads_only_the_head_of_a_long_body(strategy: str) -> None:
    # a million short lines: splitting the whole body made a million strings
    body = "a\n" * (1024 * 1024)
    tracemalloc.start()
    try:
        out = redaction.apply(strategy, body)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 4 * 1024 * 1024
    # positive control: the head of the body is still there
    assert out.startswith("a\na\n")


@pytest.mark.parametrize("strategy", ["dotenv", "htpasswd"])
def test_a_line_strategy_stops_masking_once_the_output_is_full(
    strategy: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    generic = redaction._generic

    def counted(text: str) -> str:
        calls.append(text)
        return generic(text)

    monkeypatch.setattr(redaction, "_generic", counted)
    redaction.apply(strategy, ("word " * 20 + "\n") * 80)
    # 1024 characters fill up on the 11th line of 100; the other 69 were masked for nothing
    assert len(calls) == 11


def test_htpasswd_keeps_the_user_names_and_masks_every_hash() -> None:
    out = redaction.apply("htpasswd", "alice:$apr1$abc$def123\nbob:{SHA}xyz=")
    assert out == "alice:***\nbob:***"


def test_json_env_falls_back_to_generic_masking_on_deep_nesting() -> None:
    """A body too deep to parse or to walk still has its secrets masked, and stays bounded."""
    head = f'["{_AWS_KEY}", '
    too_deep_to_parse = head + "[" * 200_000
    parsed_but_deep = head + "[" * 5000 + "]" * 5000 + "]"  # json.loads takes it; the walk not
    for body in (too_deep_to_parse, parsed_but_deep):
        out = redaction.apply("json-env", body)
        assert _AWS_KEY not in out
        assert "***redacted***" in out
        assert len(out) <= 1024


# Bytes the ``json-env`` redaction of one body near ``_JSON_PARSE_MAX`` may allocate at its peak.
# It takes about 20 MiB on the nested body below, whatever its depth; serialising the whole
# document before cutting it took several times that, more for every level of nesting.
_JSON_PEAK_BYTES = 64 * 1024 * 1024


def test_json_env_serialises_only_as_far_as_the_kept_part_reaches() -> None:
    """A deeply nested document near the parse cap is redacted within the memory bound."""
    unit = "[" * 500 + "]" * 500
    body = "[" + ",".join([unit] * ((redaction._JSON_PARSE_MAX - 2) // (len(unit) + 1))) + "]"
    assert len(body) <= redaction._JSON_PARSE_MAX  # parsed, not sent to the generic masking
    tracemalloc.start()
    try:
        out = redaction.apply("json-env", body)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert out == json.dumps(json.loads(body), indent=2)[: redaction._JSON_LIMIT]
    assert peak < _JSON_PEAK_BYTES


def test_json_env_keeps_the_head_of_the_indented_document() -> None:
    """A document longer than the kept part gives exactly the head of its indented text."""
    data = {"name": "app", "password": "hunter2", "items": [{"n": n} for n in range(500)]}
    out = redaction.apply("json-env", json.dumps(data))
    expected = json.dumps({**data, "password": "***"}, indent=2)[: redaction._JSON_LIMIT]
    assert out == expected
    assert len(out) == redaction._JSON_LIMIT


def test_a_json_body_past_the_parse_cap_gets_the_generic_masking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Past ``_JSON_PARSE_MAX`` the body is not parsed; at the cap it still is."""
    body = json.dumps({"password": "hunter2", "aws": _AWS_KEY})
    monkeypatch.setattr(redaction, "_JSON_PARSE_MAX", len(body) - 1)
    past = redaction.apply("json-env", body)
    assert past == redaction.apply("generic", body)
    assert _AWS_KEY not in past
    monkeypatch.setattr(redaction, "_JSON_PARSE_MAX", len(body))
    at_cap = redaction.apply("json-env", body)
    assert json.loads(at_cap) == {"password": "***", "aws": "***redacted***"}
