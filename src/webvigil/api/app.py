"""
The FastAPI application factory and its lifespan.

The route-handler docstrings double as the OpenAPI endpoint descriptions, so
they stay to a sentence or two; the private helpers carry the full
Args/Returns sections.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from webvigil import __version__
from webvigil.api.config import WebConfig
from webvigil.api.db import make_engine, run_alembic_upgrade
from webvigil.api.routes import auth, meta, reports, scans, setup
from webvigil.api.runner import OrchestratorFactory, ScanRunner, recover_interrupted_scans
from webvigil.api.security import resolve_session_secret


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
        """Startup: migrate, open the engine, resolve the secret, recover, start the runner."""
        if cfg.auto_migrate:
            run_alembic_upgrade(cfg)
        engine = make_engine(cfg)
        app.state.config = cfg
        app.state.engine = engine
        app.state.session_secret = resolve_session_secret(engine, cfg)
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

    app = FastAPI(title="WebVigil API", version=__version__, lifespan=lifespan)
    if cfg.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cfg.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    for router in (meta.router, setup.router, auth.router, scans.router, reports.router):
        app.include_router(router, prefix="/api")
    return app


app = create_app()
