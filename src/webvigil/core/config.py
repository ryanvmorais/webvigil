"""Scan configuration: the pydantic model, TOML loading, and CLI-override merging.

Precedence is CLI flag > config file > model default. The model mirrors
``webvigil.example.toml`` exactly and rejects unknown keys (RF-26).
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from webvigil.core.errors import ConfigError
from webvigil.core.findings import ScanMode
from webvigil.core.target import Scope

_FailOn = Literal["none", "info", "low", "medium", "high", "critical"]
_Format = Literal["json", "sarif", "html", "md"]


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScanSection(_Section):
    mode: ScanMode = ScanMode.PASSIVE
    scope: Scope = Scope.HOST
    max_pages: int = 50
    follow_robots: bool = True


class HttpSection(_Section):
    concurrency: int = 8
    delay_ms: int = 0
    timeout_s: float = 15.0
    user_agent: str = "WebVigil/0.1 (+https://github.com/ryanvmorais/webvigil)"
    verify_tls: bool = True


class ReportSection(_Section):
    format: _Format = "json"
    output: str | None = None
    fail_on: _FailOn = "none"


class ActiveSection(_Section):
    authorized_by: str


class ChecksSection(_Section):
    disabled: list[str] = []


class ScanConfig(_Section):
    """The whole configuration for one scan."""

    scan: ScanSection = ScanSection()
    http: HttpSection = HttpSection()
    report: ReportSection = ReportSection()
    active: ActiveSection | None = None
    checks: ChecksSection = ChecksSection()
    # Passthrough for the Web API's ``[web]`` table so one ``webvigil.toml`` serves both
    # tools. The engine and CLI never read it; ``webvigil.api`` parses it into its own
    # strict ``WebConfig``. Section-level typos elsewhere are still hard errors.
    web: dict[str, Any] | None = None

    @classmethod
    def load(cls, path: str | Path | None) -> ScanConfig:
        """Load a config from a TOML file, or return defaults when ``path`` is ``None``."""
        if path is None:
            return cls()
        file = Path(path)
        if not file.is_file():
            raise ConfigError(f"config file not found: {file}")
        try:
            raw = tomllib.loads(file.read_text("utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"invalid TOML in {file}: {exc}") from exc
        return cls.model_validate_or_raise(raw)

    @classmethod
    def model_validate_or_raise(cls, data: dict[str, Any]) -> ScanConfig:
        try:
            return cls.model_validate(data)
        except ValidationError as exc:
            raise ConfigError(str(exc)) from exc

    def with_overrides(self, **sections: dict[str, Any]) -> ScanConfig:
        """Return a copy with the given per-section overrides deep-merged on top.

        Only keys the caller actually passes are applied, so unset CLI flags never clobber
        file values. ``sections`` maps a section name (``scan``, ``http``, ``report``,
        ``active``, ``checks``) to a dict of the fields to override.
        """
        merged = self.model_dump()
        for name, values in sections.items():
            if not values:
                continue
            current = merged.get(name) or {}
            merged[name] = {**current, **values}
        return self.model_validate_or_raise(merged)
