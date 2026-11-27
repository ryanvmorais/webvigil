"""
The FastAPI application factory and its lifespan.

The route-handler docstrings double as the OpenAPI endpoint descriptions, so
they stay to a sentence or two; the private helpers carry the full
Args/Returns sections.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from webvigil import __version__
from webvigil.api.body_limit import BodyLimitMiddleware
from webvigil.api.cache_control import NoStoreMiddleware
from webvigil.api.client_address import TrustedProxies
from webvigil.api.config import WebConfig
from webvigil.api.db import make_engine, run_alembic_upgrade
from webvigil.api.docs_ui import install_docs
from webvigil.api.host_check import HostCheckMiddleware
from webvigil.api.origin_check import OriginCheckMiddleware
from webvigil.api.redirects import RelativeRedirectMiddleware
from webvigil.api.routes import auth, meta, reports, scans, setup
from webvigil.api.runner import OrchestratorFactory, ScanRunner, recover_interrupted_scans
from webvigil.api.security import dummy_password_hash, resolve_session_secret
from webvigil.api.throttle import LoginThrottle
from webvigil.core.output import Sink, get_logger, safe_text

# The library loggers the Web API treats (spec 025, ADR-4): the Web API owns its process, so it
# may; the engine used as a library never changes another package's logger.
_TREATED_LIBRARY_LOGGERS = ("uvicorn.error", "httpx2")


class EscapedJSONResponse(JSONResponse):
    r"""
    The API's JSON, with what an encoder writes raw shown as escapes (spec 027).

    The encoder escapes the C0 controls and leaves DEL, the C1 controls and the bidirectional and
    zero-width characters as they are, so a finding's evidence or a scan's error read with
    ``curl`` in a terminal could act on it. Each becomes a ``\uNNNN`` escape, as in the JSON
    report: the same document to a JSON parser, so the dashboard reads the same values. A ``422``
    keeps its own response, whose messages are already shown on one line (spec 025).
    """

    def render(self, content: object) -> bytes:
        """
        Args:
            content (object): The response's content, as FastAPI hands it over.

        Returns:
            bytes: The UTF-8 JSON document, escaped.
        """
        document = super().render(content).decode("utf-8")
        return safe_text(document, Sink.JSON).encode("utf-8")


async def _validation_failed(_request: Request, exc: Exception) -> JSONResponse:
    """
    Answer a request whose input failed validation, on every endpoint.

    Args:
        _request (Request): The request; unused.
        exc (Exception): The :class:`~fastapi.exceptions.RequestValidationError`.

    Returns:
        JSONResponse: ``422`` with ``{"detail": [{"type", "loc", "msg"}, ...]}``, the shape of
            FastAPI's own answer without the keys that repeat the input. A key of ``loc`` and the
            ``msg`` can quote what the client sent, so each string is bounded and its controls
            shown (the ``MESSAGE`` profile); the integer indexes of ``loc`` stay as they are.
    """
    assert isinstance(exc, RequestValidationError)
    # Where and why, never ``input``, ``ctx`` or ``url``, which echo the value sent (a password, a
    # target with a credential in it): spec 024, ADR-8.
    detail = [
        {
            "type": error["type"],
            "loc": [_message_part(part) for part in error["loc"]],
            "msg": safe_text(str(error["msg"]), Sink.MESSAGE),
        }
        for error in exc.errors()
    ]
    return JSONResponse({"detail": detail}, status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)


def _message_part(part: object) -> object:
    """
    Treat one part of a validation error's ``loc``.

    Args:
        part (object): A key (``str``) or a list index (``int``).

    Returns:
        object: A key through the ``MESSAGE`` profile, anything else unchanged.
    """
    return safe_text(part, Sink.MESSAGE) if isinstance(part, str) else part


def _treat_library_logs() -> None:
    """
    Give the library loggers that can carry scan text the ``LOG`` profile, once per process.

    Runs in the lifespan, after uvicorn has configured its loggers. ``uvicorn.error`` logs an
    exception that escapes a request, and ``httpx2`` logs the URL of every request the engine
    sends. :func:`~webvigil.core.output.get_logger` attaches the filter only once, so a second
    app in the same process adds nothing. Level and handlers stay as configured.
    """
    for name in _TREATED_LIBRARY_LOGGERS:
        get_logger(name)


def create_app(
    config: WebConfig | None = None,
    *,
    orchestrator_factory: OrchestratorFactory | None = None,
) -> FastAPI:
    """
    Build the FastAPI app: wire the lifespan, optional CORS, and the routers.

    Args:
        config (WebConfig | None): The Web-API config; loaded from file / env
            when ``None``.
        orchestrator_factory (OrchestratorFactory | None): Test seam passed
            through to the :class:`~webvigil.api.runner.ScanRunner`; ``None``
            uses the real orchestrator.

    Returns:
        FastAPI: The configured application.
    """
    cfg = config or WebConfig.load()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        """Startup: treat the logs, migrate, open the engine, resolve the secret, recover, start."""
        _treat_library_logs()
        if cfg.auto_migrate:
            run_alembic_upgrade(cfg)
        engine = make_engine(cfg)
        app.state.config = cfg
        app.state.engine = engine
        app.state.session_secret = resolve_session_secret(engine, cfg)
        dummy_password_hash()  # warm it, so the first unknown username is not slower than the rest
        recover_interrupted_scans(engine)
        runner = (
            ScanRunner(engine, orchestrator_factory=orchestrator_factory)
            if orchestrator_factory is not None
            else ScanRunner(engine)
        )
        app.state.runner = runner
        await runner.start()
        runner.wake()
        try:
            yield
        finally:
            await runner.stop()
            engine.dispose()

    # FastAPI's own /docs and /redoc load floating CDN releases without integrity; /docs is
    # served pinned by docs_ui, and ReDoc is off.
    app = FastAPI(
        title="WebVigil API",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        default_response_class=EscapedJSONResponse,
    )
    install_docs(app)
    app.add_exception_handler(RequestValidationError, _validation_failed)
    app.state.login_throttle = LoginThrottle()
    app.state.trusted_proxies = TrustedProxies(cfg.trusted_proxies)
    # Innermost: it reads the redirect the router answers with.
    app.add_middleware(RelativeRedirectMiddleware)
    if cfg.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cfg.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    # A foreign Origin on a POST / PUT / PATCH / DELETE is refused before CORS or a route sees it
    # (issue #162); the allowed list is the one CORS opens.
    app.add_middleware(OriginCheckMiddleware, allowed_origins=cfg.cors_origins)
    # An oversized body is refused before anything else (CORS included) looks at it.
    app.add_middleware(BodyLimitMiddleware)
    # The outermost check: a request addressed to a host name this server does not know is
    # refused before any other check or route runs (GHSA-q373-8m5q-qwww).
    app.add_middleware(HostCheckMiddleware, allowed_hosts=[*cfg.allowed_hosts, cfg.host])
    # Added last, so it wraps everything: every answer, a refusal of the checks above included,
    # tells caches not to store it.
    app.add_middleware(NoStoreMiddleware)
    for router in (meta.router, setup.router, auth.router, scans.router, reports.router):
        app.include_router(router, prefix="/api")
    return app


app = create_app()
