"""Security helpers: hashing, JWT lifetime, secret resolution — RF-02, RF-04, RF-07."""

from __future__ import annotations

from pathlib import Path

from webvigil.api.config import WebConfig
from webvigil.api.db import Setting, make_engine, run_alembic_upgrade, session_scope
from webvigil.api.security import (
    create_token,
    decode_token,
    hash_password,
    resolve_session_secret,
    verify_password,
)

# >= 32 bytes so PyJWT does not warn about HS256 key length.
_SECRET = "unit-test-secret-that-is-long-enough-for-hs256"
_OTHER_SECRET = "a-different-secret-also-long-enough-for-hs256"


def test_password_hash_round_trip() -> None:
    hashed = hash_password("correct horse battery staple")
    assert hashed != "correct horse battery staple"
    assert verify_password("correct horse battery staple", hashed) is True
    assert verify_password("wrong", hashed) is False


def test_verify_rejects_a_garbage_hash() -> None:
    assert verify_password("x", "not-a-hash") is False


def test_token_round_trip() -> None:
    token = create_token(42, _SECRET, ttl_hours=1)
    assert decode_token(token, _SECRET) == 42


def test_token_with_wrong_secret_is_rejected() -> None:
    token = create_token(42, _SECRET, ttl_hours=1)
    assert decode_token(token, _OTHER_SECRET) is None


def test_expired_token_is_rejected() -> None:
    token = create_token(42, _SECRET, ttl_hours=-1)  # already expired
    assert decode_token(token, _SECRET) is None
    assert decode_token("garbage", _SECRET) is None


def test_resolve_session_secret_generates_then_reuses(tmp_path: Path) -> None:
    config = WebConfig(database_path=tmp_path / "webvigil.db")
    run_alembic_upgrade(config)
    engine = make_engine(config)

    first = resolve_session_secret(engine, config)
    second = resolve_session_secret(engine, config)
    assert first == second

    with session_scope(engine) as session:
        stored = session.get(Setting, "session_secret")
        assert stored is not None and stored.value == first


def test_resolve_session_secret_prefers_the_pinned_value(tmp_path: Path) -> None:
    config = WebConfig(database_path=tmp_path / "webvigil.db", session_secret="pinned")
    run_alembic_upgrade(config)
    assert resolve_session_secret(make_engine(config), config) == "pinned"
