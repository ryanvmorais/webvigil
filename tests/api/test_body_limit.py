"""
The request-body size limit of the Web API (security audit leftovers, 1.0.1).

Real app through ``TestClient``, no mocks. A body is sent two ways because the middleware has two
paths: with a ``Content-Length`` (refused before any of it is read) and as a stream with none
(counted as it arrives, which is what ``content=<generator>`` makes httpx do).
"""

from __future__ import annotations

from collections.abc import Iterator

from fastapi.testclient import TestClient

from webvigil.api.body_limit import MAX_BODY_BYTES

_TOO_LARGE = {"detail": "request body too large"}


def _chunks(total: int, size: int = 64 * 1024) -> Iterator[bytes]:
    """
    Args:
        total (int): How many bytes to produce in all.
        size (int): The size of each chunk. Defaults to 64 KiB.

    Yields:
        bytes: Chunks of ``b"a"`` that add up to ``total`` bytes.
    """
    sent = 0
    while sent < total:
        piece = min(size, total - sent)
        yield b"a" * piece
        sent += piece


def test_a_declared_oversized_body_is_refused_with_413(client: TestClient) -> None:
    """The ``Content-Length`` alone is enough to answer 413 on an unauthenticated route."""
    response = client.post(
        "/api/auth/login",
        content=b"x" * (MAX_BODY_BYTES + 1),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json() == _TOO_LARGE


def test_a_streamed_oversized_body_is_refused_with_413(client: TestClient) -> None:
    """With no declared length the bytes are counted as they arrive and cut off at the limit."""
    response = client.post(
        "/api/auth/login",
        content=_chunks(MAX_BODY_BYTES * 4),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json() == _TOO_LARGE


def test_a_body_at_the_limit_is_not_a_413(client: TestClient) -> None:
    """The limit is on ``> MAX_BODY_BYTES``: a body of exactly that size reaches the route."""
    response = client.post(
        "/api/auth/login",
        content=b"x" * MAX_BODY_BYTES,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422  # not valid JSON: the route's own answer, not the limit's


def test_an_oversized_body_is_refused_on_an_authenticated_route(auth_client: TestClient) -> None:
    """The limit covers every route, not only the open ones."""
    response = auth_client.post(
        "/api/scans",
        content=_chunks(MAX_BODY_BYTES + 1),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413


def test_ordinary_requests_are_unaffected(auth_client: TestClient) -> None:
    """A normal scan request and a bodyless GET still work with the middleware in place."""
    created = auth_client.post("/api/scans", json={"target": "https://example.com"})
    assert created.status_code == 201
    assert auth_client.get("/api/scans").status_code == 200
