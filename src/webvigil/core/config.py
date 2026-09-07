"""
Scan configuration: the pydantic model, TOML loading, and CLI-override merging.

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

# Type aliases (PEP 695) for the two closed sets that appear in the CLI help and
# in the report section, kept in one place so the wording never drifts.
type _FailOn = Literal["none", "info", "low", "medium", "high", "critical"]
type _Format = Literal["json", "sarif", "html", "md"]


class _Section(BaseModel):
    """Base for every config section: unknown keys are a hard error (RF-26)."""

    model_config = ConfigDict(extra="forbid")


class ScanSection(_Section):
    """
    The ``[scan]`` table: crawl breadth and politeness.

    Attributes:
        mode (ScanMode): Passive (default) or Active.
        scope (Scope): How wide the crawl may reach. Defaults to
            :attr:`~webvigil.core.target.Scope.HOST`.
        max_pages (int): Hard cap on pages fetched by the crawler. Defaults
            to 50.
        follow_robots (bool): Honour ``robots.txt``. Defaults to ``True``.
        submit_forms (bool): Submit safe ``GET`` forms — search, filters —
            during the crawl to widen the surface (spec 007, RF-06). ``POST``
            forms are never submitted by the crawler. Defaults to ``True``.
    """

    mode: ScanMode = ScanMode.PASSIVE
    scope: Scope = Scope.HOST
    max_pages: int = 50
    follow_robots: bool = True
    submit_forms: bool = True


class HttpSection(_Section):
    """
    The ``[http]`` table: transport tuning for the shared client.

    Attributes:
        concurrency (int): Maximum in-flight requests. Defaults to 8.
        delay_ms (int): Delay inserted between requests, in milliseconds.
            Defaults to 0.
        timeout_s (float): Per-request timeout, in seconds. Defaults to 15.0.
        user_agent (str): ``User-Agent`` header sent on every request.
        verify_tls (bool): Verify the target's TLS certificate. Defaults to
            ``True``.
    """

    concurrency: int = 8
    delay_ms: int = 0
    timeout_s: float = 15.0
    user_agent: str = "WebVigil/0.1 (+https://github.com/ryanvmorais/webvigil)"
    verify_tls: bool = True


class ReportSection(_Section):
    """
    The ``[report]`` table: default output shape.

    Attributes:
        format (_Format): Report format. Defaults to ``"json"``, the canonical
            form every other reporter is derived from.
        output (str | None): Path to write the report to, or ``None`` for
            stdout.
        fail_on (_FailOn): Lowest severity that makes the process exit
            non-zero. Defaults to ``"none"``.
    """

    format: _Format = "json"
    output: str | None = None
    fail_on: _FailOn = "none"


class ActiveSection(_Section):
    """
    The ``[active]`` table: the Active-Mode authorization gate.

    Attributes:
        authorized_by (str): Required attestation naming who authorized the
            Active scan (a person, an engagement). The scan refuses to run
            Active Mode without it.
    """

    authorized_by: str


class AuthSection(_Section):
    """
    Static credentials for an authenticated scan (spec 007). Cookies only in v0.7.

    Each ``cookies`` entry is a ``name=value`` string.
    :class:`~webvigil.http.client.HttpClient` attaches them to requests whose
    host is the target host and to no other, and no cookie value ever reaches
    a report, a log line, or the scan metadata (RF-01, RF-02).

    Attributes:
        cookies (list[str]): Cookie pairs, each ``"name=value"``. Defaults to
            empty (an unauthenticated scan).
    """

    cookies: list[str] = []

    @field_validator("cookies")
    @classmethod
    def _check_pairs(cls, raw: list[str]) -> list[str]:
        """
        Reject any cookie entry that is not a ``name=value`` pair.

        Args:
            raw (list[str]): The configured cookie entries.

        Returns:
            list[str]: ``raw`` unchanged when every entry is well formed.

        Raises:
            ValueError: If an entry has no ``=`` or an empty name.
        """
        for entry in raw:
            name, sep, _value = entry.partition("=")
            if not sep or not name.strip():
                raise ValueError(f"invalid cookie {entry!r}: expected 'name=value'")
        return raw

    @property
    def as_header(self) -> str:
        """
        Returns:
            str: The joined ``Cookie:`` header value, or ``""`` when no cookies
                are configured.
        """
        return "; ".join(entry.strip() for entry in self.cookies)


class ChecksSection(_Section):
    """
    The ``[checks]`` table: check selection.

    Attributes:
        disabled (list[str]): Check ids to skip. Unknown ids raise a scan
            warning rather than an error. Defaults to empty.
    """

    disabled: list[str] = []


class DisclosureSection(_Section):
    """
    Information-disclosure probing (spec 005). Opt-in, GET-only, unrelated to Active Mode.

    Attributes:
        probe (bool): Probe a curated catalogue of sensitive paths (``.git``,
            ``.env``, backups, debug endpoints). Defaults to ``False``.
    """

    probe: bool = False


class InjectionSection(_Section):
    """
    Active-injection tuning (spec 006, spec 008). Only consulted on an Active scan.

    Attributes:
        request_budget (int): Total crafted requests the injection pass may
            spend. Defaults to 500.
        max_injection_points (int): Cap on enumerated injection points.
            Defaults to 200.
        time_based_sqli (bool): Send time-delay SQLi payloads. Defaults to
            ``True``.
        time_based_delay_s (int): Delay a positive time-based SQLi payload
            should induce, in seconds. Defaults to 5.
        stored_xss (bool): Run the opt-in stored/persistent-XSS pass. Off by
            default: the pass submits marker payloads the target stores and
            does not remove them (see ``docs/active-injection.md``).
    """

    request_budget: int = 500
    max_injection_points: int = 200
    time_based_sqli: bool = True
    time_based_delay_s: int = 5
    stored_xss: bool = False


class DepsSection(_Section):
    """
    Dependency-fingerprint tuning (spec 004, spec 010).

    ``osv_online`` is the only option that makes the engine reach a host other
    than the target: with it on, the names and versions of the client-side
    libraries the scan detected are sent to ``osv_base_url`` (OSV.dev) for a
    known-vulnerability lookup that augments the vendored, offline Retire.js
    match. Off by default; see ``docs/dependency-fingerprinting.md``.

    Attributes:
        osv_online (bool): Enable the OSV.dev lookup. Defaults to ``False``.
        osv_timeout_s (float): Per-request timeout for the OSV calls, in
            seconds. Defaults to 10.0.
        osv_base_url (str): Base URL of the OSV.dev API.
    """

    osv_online: bool = False
    osv_timeout_s: float = 10.0
    osv_base_url: str = "https://api.osv.dev"


class ScanConfig(_Section):
    """
    The whole configuration for one scan.

    Attributes:
        scan (ScanSection): Crawl breadth and politeness.
        http (HttpSection): Transport tuning.
        report (ReportSection): Default output shape.
        active (ActiveSection | None): Active-Mode authorization, or ``None``.
        auth (AuthSection): Static credentials for an authenticated scan.
        checks (ChecksSection): Check selection.
        disclosure (DisclosureSection): Information-disclosure probing.
        injection (InjectionSection): Active-injection tuning.
        deps (DepsSection): Dependency-fingerprint tuning.
        web (dict[str, Any] | None): Passthrough for the Web API's ``[web]``
            table so one ``webvigil.toml`` serves both tools. The engine and
            CLI never read it; ``webvigil.api`` parses it into its own strict
            ``WebConfig``. Section-level typos elsewhere are still hard errors.
    """

    scan: ScanSection = ScanSection()
    http: HttpSection = HttpSection()
    report: ReportSection = ReportSection()
    active: ActiveSection | None = None
    auth: AuthSection = AuthSection()
    checks: ChecksSection = ChecksSection()
    disclosure: DisclosureSection = DisclosureSection()
    injection: InjectionSection = InjectionSection()
    deps: DepsSection = DepsSection()
    web: dict[str, Any] | None = None

    @classmethod
    def load(cls, path: str | Path | None) -> ScanConfig:
        """
        Load a config from a TOML file, or return defaults when ``path`` is ``None``.

        Args:
            path (str | Path | None): Path to a ``webvigil.toml``, or ``None``
                to use the model defaults.

        Returns:
            ScanConfig: The validated configuration.

        Raises:
            ConfigError: If the file is missing, is not valid TOML, or fails
                model validation.
        """
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
        """
        Validate a raw config mapping, translating pydantic errors to :class:`ConfigError`.

        Args:
            data (dict[str, Any]): The parsed TOML mapping.

        Returns:
            ScanConfig: The validated configuration.

        Raises:
            ConfigError: If ``data`` fails model validation.
        """
        try:
            return cls.model_validate(data)
        except ValidationError as exc:
            raise ConfigError(str(exc)) from exc

    def with_overrides(self, **sections: dict[str, Any]) -> ScanConfig:
        """
        Return a copy with the given per-section overrides deep-merged on top.

        Only keys the caller actually passes are applied, so unset CLI flags
        never clobber file values.

        Args:
            **sections (dict[str, Any]): Maps a section name (``scan``,
                ``http``, ``report``, ``active``, ``auth``, ``checks``,
                ``disclosure``, ``injection``, ``deps``) to a dict of the
                fields to override. ``injection`` covers spec 006 tuning plus
                spec 008's ``stored_xss``; ``deps`` covers spec 010's
                ``osv_online``.

        Returns:
            ScanConfig: A new, validated configuration.

        Raises:
            ConfigError: If the merged result fails model validation.
        """
        merged = self.model_dump()
        for name, values in sections.items():
            if not values:
                continue
            current = merged.get(name) or {}
            merged[name] = {**current, **values}
        return self.model_validate_or_raise(merged)
