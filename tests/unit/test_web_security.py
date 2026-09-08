"""
Security helpers: hashing, JWT lifetime, secret resolution — RF-02, RF-04, RF-07.

Small, direct unit tests: password hash / verify round-trips, token
create / decode with the right and wrong secret and past expiry, and
``resolve_session_secret`` generating a secret once, persisting it in the
``setting`` table, and reusing it — with a pinned value taking precedence.
``_SECRET`` / ``_OTHER_SECRET`` are >= 32 bytes so PyJWT does not warn.
"""

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
    """A hashed password is not the plaintext and verifies only against the right password."""
    hashed = hash_password("correct horse battery staple")
    assert hashed != "correct horse battery staple"
    assert verify_password("correct horse battery staple", hashed) is True
    assert verify_password("wrong", hashed) is False


def test_verify_rejects_a_garbage_hash() -> None:
    """``verify_password`` against a non-hash string is ``False``, not an exception."""
    assert verify_password("x", "not-a-hash") is False


def test_token_round_trip() -> None:
    """A token created for a user id decodes back to that id with the same secret."""
    token = create_token(42, _SECRET, ttl_hours=1)
    assert decode_token(token, _SECRET) == 42


def test_token_with_wrong_secret_is_rejected() -> None:
    """A token decoded with the wrong secret yields ``None``."""
    token = create_token(42, _SECRET, ttl_hours=1)
    assert decode_token(token, _OTHER_SECRET) is None


def test_expired_token_is_rejected() -> None:
    """An expired token, and outright garbage, both decode to ``None``."""
    token = create_token(42, _SECRET, ttl_hours=-1)  # already expired
    assert decode_token(token, _SECRET) is None
    assert decode_token("garbage", _SECRET) is None


def test_resolve_session_secret_generates_then_reuses(tmp_path: Path) -> None:
    """``resolve_session_secret`` generates a secret once, stores it, and reuses it after."""
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
    """A config-pinned ``session_secret`` is used verbatim, not replaced by a generated one."""
    config = WebConfig(database_path=tmp_path / "webvigil.db", session_secret="pinned")
    run_alembic_upgrade(config)
    assert resolve_session_secret(make_engine(config), config) == "pinned"
