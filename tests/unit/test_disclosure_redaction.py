"""
Secret redaction for probe evidence — RNF-06, ADR-9.
"""

from __future__ import annotations

import json

from webvigil.checks.disclosure import redaction

_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
_HEX40 = "a" * 45
_PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc123\n-----END RSA PRIVATE KEY-----"


def test_dotenv_keeps_keys_and_masks_values() -> None:
    body = f"# comment\nexport AWS_ACCESS_KEY_ID={_AWS_KEY}\nDB_PASSWORD=hunter2\nEMPTY=\n"
    out = redaction.apply("dotenv", body)
    assert "AWS_ACCESS_KEY_ID" in out
    assert "DB_PASSWORD" in out
    assert _AWS_KEY not in out
    assert "hunter2" not in out
    assert "# comment" in out


def test_json_env_keeps_names_and_masks_values() -> None:
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
    body = f"key={_AWS_KEY} hash={_HEX40}\n{_PEM}"
    out = redaction.apply("generic", body)
    assert _AWS_KEY not in out
    assert _HEX40 not in out
    assert "PRIVATE KEY" not in out or "BEGIN RSA PRIVATE KEY" not in out


def test_every_strategy_is_length_bounded() -> None:
    big = "SECRET_KEY=" + "x" * 20000 + "\n"
    for strategy in ("dotenv", "json-env", "generic", "none"):
        assert len(redaction.apply(strategy, big)) <= 2000


def test_none_strategy_still_bounds_but_keeps_structure() -> None:
    out = redaction.apply("none", "line1\nline2\n" + "z" * 5000)
    assert out.startswith("line1")
    assert len(out) <= 1024
