"""Web API configuration: the ``[web]`` table of ``webvigil.toml`` plus env overrides."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from webvigil.core.errors import ConfigError

_ENV_PREFIX = "WEBVIGIL_"


class WebConfig(BaseModel):
    """
    Everything the Web API needs to run. API-only — the engine never reads this.

    Attributes:
        database_path (Path): SQLite file path. Defaults to ``webvigil.db``.
        host (str): Bind host. Defaults to ``127.0.0.1``.
        port (int): Bind port. Defaults to 8000.
        session_secret (str | None): Pinned JWT signing secret; when ``None`` a
            secret is generated and stored in the database on first use.
        session_ttl_hours (int): Session lifetime, in hours. Defaults to 12.
        cookie_secure (bool): Set the ``Secure`` flag on the session cookie.
            Defaults to ``False`` (development over HTTP).
        auto_migrate (bool): Run ``alembic upgrade head`` on startup. Defaults
            to ``True``.
        cors_origins (list[str]): Allowed CORS origins. Defaults to empty (the
            bundled UI is same-origin).
    """

    model_config = ConfigDict(extra="forbid")

    database_path: Path = Path("webvigil.db")
    host: str = "127.0.0.1"
    port: int = 8000
    session_secret: str | None = None
    session_ttl_hours: int = 12
    cookie_secure: bool = False
    auto_migrate: bool = True
    cors_origins: list[str] = []

    @classmethod
    def load(cls, path: str | Path | None = None) -> WebConfig:
        """
        Build a config from the ``[web]`` table of ``path``, then env vars.

        Args:
            path (str | Path | None): Path to a ``webvigil.toml``. When omitted,
                ``WEBVIGIL_CONFIG`` is used if set; when that is also unset, only
                defaults and env vars apply.

        Returns:
            WebConfig: The validated configuration.

        Raises:
            ConfigError: If the file is missing, is not valid TOML, has a
                non-table ``[web]``, or fails model validation.
        """
        path = path if path is not None else os.environ.get("WEBVIGIL_CONFIG")
        data: dict[str, Any] = {}
        if path is not None:
            file = Path(path)
            if not file.is_file():
                raise ConfigError(f"config file not found: {file}")
            try:
                raw = tomllib.loads(file.read_text("utf-8"))
            except tomllib.TOMLDecodeError as exc:
                raise ConfigError(f"invalid TOML in {file}: {exc}") from exc
            section = raw.get("web")
            if section is not None:
                if not isinstance(section, dict):
                    raise ConfigError("[web] must be a table")
                data.update(section)

        data.update(_env_overrides())
        try:
            return cls.model_validate(data)
        except ValidationError as exc:
            raise ConfigError(str(exc)) from exc


def _env_overrides() -> dict[str, Any]:
    """
    Read ``WEBVIGIL_*`` environment variables into a config-field mapping.

    Returns:
        dict[str, Any]: The overrides, with ``port`` / ``session_ttl_hours``
            coerced to ``int``, the boolean flags parsed loosely, and
            ``cors_origins`` split on commas.
    """
    out: dict[str, Any] = {}
    mapping = {
        "DATABASE_PATH": "database_path",
        "WEB_HOST": "host",
        "WEB_PORT": "port",
        "SESSION_SECRET": "session_secret",
        "SESSION_TTL_HOURS": "session_ttl_hours",
        "COOKIE_SECURE": "cookie_secure",
        "AUTO_MIGRATE": "auto_migrate",
        "CORS_ORIGINS": "cors_origins",
    }
    for env_suffix, field in mapping.items():
        value = os.environ.get(f"{_ENV_PREFIX}{env_suffix}")
        if value is None:
            continue
        if field in ("port", "session_ttl_hours"):
            out[field] = int(value)
        elif field in ("cookie_secure", "auto_migrate"):
            out[field] = value.strip().lower() in ("1", "true", "yes", "on")
        elif field == "cors_origins":
            out[field] = [origin.strip() for origin in value.split(",") if origin.strip()]
        else:
            out[field] = value
    return out
