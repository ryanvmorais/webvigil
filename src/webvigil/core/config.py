"""Scan configuration: the pydantic model, TOML loading, and CLI-override merging.

Precedence is CLI flag > config file > model default. The model mirrors
``webvigil.example.toml`` exactly and rejects unknown keys (RF-26).
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

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
    # Submit safe GET forms (search, filters) during the crawl (spec 007, RF-06). POST forms
    # are never submitted by the crawler.
    submit_forms: bool = True


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


class AuthSection(_Section):
    """Static credentials for an authenticated scan (spec 007). Cookies only in v0.7.

    Each ``cookies`` entry is a ``name=value`` string. :class:`~webvigil.http.client.HttpClient`
    attaches them to requests whose host is the target host and to no other, and no cookie
    value ever reaches a report, a log line, or the scan metadata (RF-01, RF-02).
    """

    cookies: list[str] = []

    @field_validator("cookies")
    @classmethod
    def _check_pairs(cls, raw: list[str]) -> list[str]:
        for entry in raw:
            name, sep, _value = entry.partition("=")
            if not sep or not name.strip():
                raise ValueError(f"invalid cookie {entry!r}: expected 'name=value'")
        return raw

    @property
    def as_header(self) -> str:
        """The joined ``Cookie:`` header value, or ``""`` when no cookies are configured."""
        return "; ".join(entry.strip() for entry in self.cookies)


class ChecksSection(_Section):
    disabled: list[str] = []


class DisclosureSection(_Section):
    """Information-disclosure probing (spec 005). Opt-in, GET-only, unrelated to Active Mode."""

    probe: bool = False


class InjectionSection(_Section):
    """Active-injection tuning (spec 006, spec 008). Only consulted on an Active scan."""

    request_budget: int = 500
    max_injection_points: int = 200
    time_based_sqli: bool = True
    time_based_delay_s: int = 5
    # spec 008 — opt-in stored/persistent-XSS pass. Off by default: the pass submits marker
    # payloads the target stores and does not remove them (see docs/active-injection.md).
    stored_xss: bool = False


class DepsSection(_Section):
    """Dependency-fingerprint tuning (spec 004, spec 010).

    ``osv_online`` is the only option that makes the engine reach a host other than the
    target: with it on, the names and versions of the client-side libraries the scan
    detected are sent to ``osv_base_url`` (OSV.dev) for a known-vulnerability lookup that
    augments the vendored, offline Retire.js match. Off by default; see
    ``docs/dependency-fingerprinting.md``.
    """

    osv_online: bool = False
    osv_timeout_s: float = 10.0
    osv_base_url: str = "https://api.osv.dev"


class ScanConfig(_Section):
    """The whole configuration for one scan."""

    scan: ScanSection = ScanSection()
    http: HttpSection = HttpSection()
    report: ReportSection = ReportSection()
    active: ActiveSection | None = None
    auth: AuthSection = AuthSection()
    checks: ChecksSection = ChecksSection()
    disclosure: DisclosureSection = DisclosureSection()
    injection: InjectionSection = InjectionSection()
    deps: DepsSection = DepsSection()
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
        ``active``, ``auth``, ``checks``, ``disclosure``, ``injection``, ``deps``) to a dict
        of the fields to override. ``injection`` covers spec 006 tuning plus spec 008's
        ``stored_xss``; ``deps`` covers spec 010's ``osv_online``.
        """
        merged = self.model_dump()
        for name, values in sections.items():
            if not values:
                continue
            current = merged.get(name) or {}
            merged[name] = {**current, **values}
        return self.model_validate_or_raise(merged)
