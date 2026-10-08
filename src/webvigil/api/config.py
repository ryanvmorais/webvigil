"""Web API configuration: the ``[web]`` table of ``webvigil.toml`` plus env overrides."""

from __future__ import annotations

import ipaddress
import os
import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from webvigil.core.errors import ConfigError

_ENV_PREFIX = "WEBVIGIL_"
# HS256 wants a key as long as its 32-byte digest; PyJWT already warns below that. A pinned secret
# shorter than this is refused at start (the generated one is 64 characters).
MIN_SESSION_SECRET_LENGTH = 32


class WebConfig(BaseModel):
    """
    Everything the Web API needs to run. API-only — the engine never reads this.

    Attributes:
        database_path (Path): SQLite file path. Defaults to ``webvigil.db``.
        host (str): Bind host. Defaults to ``127.0.0.1``.
        port (int): Bind port. Defaults to 8000.
        session_secret (str | None): Pinned JWT signing secret, at least
            ``MIN_SESSION_SECRET_LENGTH`` characters; when ``None`` (or empty) a
            secret is generated and stored in the database on first use.
        session_ttl_hours (int): Session lifetime, in hours. Defaults to 12.
        cookie_secure (bool): Set the ``Secure`` flag on the session cookie.
            Defaults to ``False`` (development over HTTP).
        auto_migrate (bool): Run ``alembic upgrade head`` on startup. Defaults
            to ``True``.
        cors_origins (list[str]): Allowed CORS origins; ``*`` is refused because the
            API sends credentials. Defaults to empty (the bundled UI is same-origin).
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

    @field_validator("session_secret")
    @classmethod
    def _secret_is_long_enough(cls, value: str | None) -> str | None:
        """
        Args:
            value (str | None): The pinned secret; empty or ``None`` means "generate one".

        Returns:
            str | None: ``value`` unchanged.

        Raises:
            ValueError: If a non-empty secret is shorter than ``MIN_SESSION_SECRET_LENGTH`` bytes.
        """
        if value and len(value.encode("utf-8")) < MIN_SESSION_SECRET_LENGTH:
            raise ValueError(
                f"session_secret must be at least {MIN_SESSION_SECRET_LENGTH} characters "
                "(generate one with: "
                "python -c 'import secrets; print(secrets.token_urlsafe(48))'), "
                "or leave it unset to have one generated and stored in the database"
            )
        return value

    @field_validator("cors_origins")
    @classmethod
    def _no_wildcard_origin(cls, value: list[str]) -> list[str]:
        """
        Args:
            value (list[str]): The allowed origins.

        Returns:
            list[str]: ``value`` unchanged.

        Raises:
            ValueError: If ``*`` is listed: the API sends credentials, which a wildcard origin
                would hand to every site.
        """
        if "*" in value:
            raise ValueError(
                "cors_origins must list origins explicitly: '*' is not allowed because the API "
                "sends credentials (the session cookie)"
            )
        return value

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


def insecure_bind_warning(config: WebConfig, host: str) -> str | None:
    """
    Say so when the API listens beyond this machine and the session cookie is not marked ``Secure``.

    A warning, not a refusal: ``docker compose`` binds ``0.0.0.0`` inside the container and
    publishes the port on ``127.0.0.1`` only, and a TLS-terminating proxy is the other legitimate
    setup.

    Args:
        config (WebConfig): Supplies ``cookie_secure``.
        host (str): The address the server will bind (the ``--host`` flag wins over the config).

    Returns:
        str | None: The warning text, or ``None`` when the host is a loopback address or the cookie
            is ``Secure``.
    """
    if config.cookie_secure:
        return None
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:  # a name, not an address
        loopback = host.lower() == "localhost"
    if loopback:
        return None
    return (
        f"listening on {host}, which other machines can reach, with cookie_secure off: the "
        "session cookie travels without the Secure flag. Serve it over HTTPS and set "
        "cookie_secure = true, or bind 127.0.0.1 (docker compose publishes on 127.0.0.1 only)"
    )
