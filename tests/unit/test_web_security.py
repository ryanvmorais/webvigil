"""
Security helpers: hashing, JWT lifetime, secret resolution — RF-02, RF-04, RF-07.

Small, direct unit tests: password hash / verify round-trips, token
create / decode with the right and wrong secret and past expiry, and
``resolve_session_secret`` generating a secret once, persisting it in the
``setting`` table, and reusing it — with a pinned value taking precedence.
``_SECRET`` / ``_OTHER_SECRET`` are >= 32 bytes so PyJWT does not warn.
"""

from __future__ import annotations

import time
from pathlib import Path

import jwt

from webvigil.api.config import WebConfig
from webvigil.api.db import Setting, make_engine, run_alembic_upgrade, session_scope
from webvigil.api.security import (
    create_token,
    decode_token,
    dummy_password_hash,
    hash_password,
    resolve_session_secret,
    verify_password,
)

# >= 32 bytes so PyJWT does not warn about HS256 key length.
_SECRET = "unit-test-secret-that-is-long-enough-for-hs256"
_OTHER_SECRET = "a-different-secret-also-long-enough-for-hs256"
_PINNED = "pinned-" + "p" * 32


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
    """A token decodes back to its user id, stamped with the time it was issued."""
    before = int(time.time())
    token = create_token(42, _SECRET, ttl_hours=1)
    claims = decode_token(token, _SECRET)
    assert claims is not None
    assert claims.user_id == 42
    assert before <= claims.issued_at <= int(time.time())


def test_token_without_an_issue_time_is_rejected() -> None:
    """A token with no ``iat`` cannot be compared with a password change, so it is refused."""
    token = jwt.encode({"sub": "42", "exp": int(time.time()) + 3600}, _SECRET, algorithm="HS256")
    assert decode_token(token, _SECRET) is None


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
    config = WebConfig(database_path=tmp_path / "webvigil.db", session_secret=_PINNED)
    run_alembic_upgrade(config)
    assert resolve_session_secret(make_engine(config), config) == _PINNED


def test_the_dummy_hash_is_a_real_argon2_hash_with_the_parameters_of_a_real_one() -> None:
    """Verifying against it costs what a real check costs, and nobody's password matches it."""
    dummy = dummy_password_hash()
    real = hash_password("anything")
    # "$argon2id$v=19$m=...,t=...,p=...$salt$digest": everything before the salt is the cost.
    assert dummy.split("$")[:4] == real.split("$")[:4]
    assert dummy_password_hash() == dummy  # built once
    assert verify_password("", dummy) is False and verify_password("anything", dummy) is False
