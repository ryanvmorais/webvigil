"""
The failure table of spec 027 (RF-01, RF-02, ADR-1): the stages, the kinds of failure, the
markers and the fault plan.

Each stage is a place where a scan, the CLI or the Web API depends on something that can fail: a
pass of :meth:`~webvigil.core.orchestrator.Orchestrator.run`, the crawl, a file, the resolver, the
database. Its row names the seam the suite wraps and the kinds of failure it gets.
:data:`DEPENDENCIES` gives every network client, file operation and database statement of the
source the stage whose failure covers it, and ``tests/failure/test_table.py`` keeps both in step
with the code (RF-06).

A failure's text is its marker followed by :data:`HOSTILE`, so a search finds where it went and
also sees whether the output cut it and showed its controls (RF-01, RF-04).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Literal

from webvigil.core.bounded import TEXT_MAX_CHARS


class Kind(StrEnum):
    """
    A kind of failure the suite injects.

    Attributes:
        REFUSED: ``httpx2.ConnectError``.
        RESET: ``httpx2.ReadError``.
        TIMEOUT: ``httpx2.ReadTimeout``.
        SERVER_ERROR: A ``503`` whose body and headers carry the marker.
        BAD_BODY: A ``gzip`` ``Content-Encoding`` over bytes that are not gzip; for the OSV lookup,
            a ``200`` whose body is not JSON; for a file, content that does not parse.
        RAISES: A ``RuntimeError`` from inside the call, not an ``httpx2`` error.
        RESOLVER: The address guard's resolver raises.
        FILE_READ: ``OSError`` reading an input file.
        FILE_WRITE: ``OSError`` writing a report.
        DB: A statement that raises (``sqlalchemy.exc.OperationalError``).
    """

    REFUSED = "refused"
    RESET = "reset"
    TIMEOUT = "timeout"
    SERVER_ERROR = "server-error"
    BAD_BODY = "bad-body"
    RAISES = "raises"
    RESOLVER = "resolver"
    FILE_READ = "file-read"
    FILE_WRITE = "file-write"
    DB = "db"


@dataclass(frozen=True)
class Stage:
    """
    One row of the table.

    Attributes:
        name (str): The stage's name, as markers and :data:`DEPENDENCIES` spell it.
        seam (str): What the suite wraps to fail it: ``Class.method`` for a pass the scan harness
            attributes, or the dotted name of the function a CLI or API run patches.
        harness (Literal["scan", "cli", "api"]): Which harness runs it.
        kinds (tuple[Kind, ...]): The kinds of failure it gets, in rotation order.
    """

    name: str
    seam: str
    harness: Literal["scan", "cli", "api"]
    kinds: tuple[Kind, ...]


# The kinds every network stage of the scan harness gets, one per run (ADR-1).
NETWORK_KINDS: Final = (
    Kind.REFUSED,
    Kind.RESET,
    Kind.TIMEOUT,
    Kind.SERVER_ERROR,
    Kind.BAD_BODY,
    Kind.RAISES,
)


def _scan(name: str, seam: str) -> Stage:
    """
    Args:
        name (str): The stage's name.
        seam (str): The pass method the scan harness wraps.

    Returns:
        Stage: A network stage of the scan harness.
    """
    return Stage(name, seam, "scan", NETWORK_KINDS)


# The scan stages in the order ``Orchestrator.run`` reaches them, then the CLI's and the Web API's.
# ``target`` is the target URL itself, whichever pass asks for it: the crawl must not lose it in
# the other stages' runs.
STAGES: Final[tuple[Stage, ...]] = (
    _scan("login", "Orchestrator._log_in"),
    _scan("openapi", "Orchestrator._load_openapi"),
    _scan("target", "Target.entry_url"),
    _scan("crawl", "Crawler.discover"),
    _scan("fingerprint", "Orchestrator._fingerprint"),
    _scan("osv", "Orchestrator._osv_lookup"),
    _scan("probe", "Orchestrator._probe_disclosure"),
    _scan("injection", "Orchestrator._inject"),
    _scan("stored-xss", "Orchestrator._inject_stored"),
    _scan("envelope", "Orchestrator._scan_envelope"),
    _scan("upload", "Orchestrator._scan_upload"),
    _scan("csrf", "Orchestrator._scan_csrf"),
    _scan("session", "Orchestrator._scan_session"),
    _scan("checks", "Orchestrator._run_checks"),
    Stage("resolver", "webvigil.http.addresses.system_resolver", "cli", (Kind.RESOLVER,)),
    Stage("config-read", "webvigil.core.config.read_toml", "cli", (Kind.FILE_READ,)),
    Stage("openapi-read", "webvigil.crawler.openapi._fetch_document", "cli", (Kind.FILE_READ,)),
    Stage("openapi-parse", "webvigil.crawler.openapi._fetch_document", "cli", (Kind.BAD_BODY,)),
    Stage("har-read", "Orchestrator._load_har", "cli", (Kind.FILE_READ,)),
    Stage("report-render", "webvigil.cli.app._rendered", "cli", (Kind.RAISES,)),
    Stage("report-write", "webvigil.cli.app._write_report", "cli", (Kind.FILE_WRITE,)),
    Stage("report-read", "webvigil.reporting.load_result", "cli", (Kind.FILE_READ,)),
    Stage("api-engine", "webvigil.api.runner.ScanRunner._run_scan", "api", (Kind.RAISES,)),
    Stage("api-store", "webvigil.api.runner.ScanRunner._store", "api", (Kind.DB,)),
    Stage("api-claim", "webvigil.api.runner.ScanRunner._claim_next_queued", "api", (Kind.DB,)),
    Stage("api-proxies", "webvigil.api.client_address._resolve_name", "api", (Kind.RESOLVER,)),
)

STAGE_NAMES: Final = frozenset(stage.name for stage in STAGES)

# How many scan runs give every scan stage every one of its kinds (ADR-1).
SCAN_RUNS: Final = len(NETWORK_KINDS)

# The stage of any database statement or file of the Web API other than the claim of a queued scan.
_DB_STATEMENT = "api-store"

# Every network client, file operation and database statement of the source, by its key in the
# destination inventory (``CONNECTIONS`` of spec 026) or the sensitive-point inventory (its
# ``file`` and ``sql`` points), with the stage whose failure covers it. A new one is a new line
# here, in the pull request that adds it.
DEPENDENCIES: Final[Mapping[str, str]] = {
    # the network
    "webvigil.http.client:HttpClient.__aenter__": "crawl",
    "webvigil.checks.deps.osv:OsvProvider._client": "osv",
    "webvigil.http.tls_probe:_handshake": "checks",
    "webvigil.http.addresses:system_resolver": "resolver",
    "webvigil.api.client_address:_resolve_name": "api-proxies",
    # the files
    "webvigil.checks.deps._data:load_raw_db file .read_text": "fingerprint",
    "webvigil.checks.deps._data:load_provenance file .read_text": "fingerprint",
    "webvigil.checks.disclosure.catalogue:load_catalogue file .read_text": "probe",
    "webvigil.checks.disclosure.catalogue:backup_spec file .read_text": "probe",
    "webvigil.core.suffixes:load_rules file .read_text": "target",
    "webvigil.core.config:read_toml file file.read_text": "config-read",
    "webvigil.crawler.openapi:_fetch_document file path.read_text": "openapi-read",
    "webvigil.crawler.har:_read_entries file source.read_bytes": "har-read",
    "webvigil.cli.app:_write_report file output.write_text": "report-write",
    "webvigil.reporting:load_result file .open": "report-read",
    "webvigil.api.db:secure_database_files file os.open": _DB_STATEMENT,
    # the database
    "webvigil.api.cli:reset_password sql session.exec": _DB_STATEMENT,
    "webvigil.api.routes.auth:login sql session.exec": _DB_STATEMENT,
    "webvigil.api.routes.reports:download_report sql session.exec": _DB_STATEMENT,
    "webvigil.api.routes.scans:create_scan sql session.exec": _DB_STATEMENT,
    "webvigil.api.routes.scans:list_scans sql session.exec": _DB_STATEMENT,
    "webvigil.api.routes.scans:list_findings sql session.exec": _DB_STATEMENT,
    "webvigil.api.routes.scans:list_findings sql session.exec#2": _DB_STATEMENT,
    "webvigil.api.routes.scans:list_finding_checks sql session.exec": _DB_STATEMENT,
    "webvigil.api.routes.setup:_user_count sql session.exec": _DB_STATEMENT,
    "webvigil.api.runner:ScanRunner._claim_next_queued sql session.exec": "api-claim",
    "webvigil.api.runner:recover_interrupted_scans sql session.exec": "api-claim",
    "webvigil.api.security:store_password_hash sql session.exec": _DB_STATEMENT,
    "webvigil.api.security:store_password_hash sql session.exec#2": _DB_STATEMENT,
}

# ---------------------------------------------------------------------------
# The markers (RF-01)
# ---------------------------------------------------------------------------

# What follows a failure's marker: an escape sequence, a CR LF that imitates a log line, a
# right-to-left override, a zero-width space and padding past the 16 Ki bound of ``Text``. Built
# with ``chr`` so the source holds no invisible character.
PAD_CHAR: Final = "P"
HOSTILE: Final = "".join(
    (
        chr(0x1B),
        "[31m",
        "\r\n",
        "2026-01-01 00:00:00 INFO webvigil the scan finished",
        chr(0x202E),
        "gnp.exe",
        chr(0x200B),
        PAD_CHAR * (TEXT_MAX_CHARS + 4 * 1024),
    )
)


def _hex8(seed: str) -> str:
    """
    Args:
        seed (str): What names the marker.

    Returns:
        str: Eight hex digits of the seed's SHA-256: fixed, so a run repeats.
    """
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8]


def credential_marker(name: str) -> str:
    """
    Args:
        name (str): What the credential is (``cookie``, ``bearer``, ``password``...).

    Returns:
        str: ``wv-cred-<name>-<hex8>``, a value that appears nowhere else.
    """
    return f"wv-cred-{name}-{_hex8(f'cred:{name}')}"


def failure_marker(stage: str, kind: Kind) -> str:
    """
    Args:
        stage (str): The stage's name.
        kind (Kind): The kind of failure.

    Returns:
        str: ``wv-fail-<stage>-<kind>-<hex8>``, which names where a match came from.
    """
    return f"wv-fail-{stage}-{kind}-{_hex8(f'fail:{stage}:{kind}')}"


def failure_text(marker: str) -> str:
    """
    Args:
        marker (str): A failure marker.

    Returns:
        str: The text an injected failure carries: the marker, then :data:`HOSTILE`.
    """
    return marker + HOSTILE


def stage(name: str) -> Stage:
    """
    Args:
        name (str): A stage's name.

    Returns:
        Stage: Its row.

    Raises:
        KeyError: If no row has that name.
    """
    for row in STAGES:
        if row.name == name:
            return row
    raise KeyError(name)


# ---------------------------------------------------------------------------
# The fault plan (RF-02, ADR-1)
# ---------------------------------------------------------------------------

# The fixture's target URL: the scan harness's ``target`` stage, exempt from the other stages'
# failures for good, so one failure does not end the scan before the later stages.
TARGET: Final = "http://demo.test/"
_BUCKETS: Final = 8


def kind_for(run: int, row: Stage) -> Kind:
    """
    Args:
        run (int): The run number, from 0.
        row (Stage): A stage.

    Returns:
        Kind: The stage's kind in that run. It moves one row per run, so over
            ``len(row.kinds)`` runs the stage gets each of its kinds once, and two neighbouring
            stages never get the same kind in one run.
    """
    position = STAGES.index(row)
    return row.kinds[(run + position) % len(row.kinds)]


def _bucket(url: str) -> int:
    """
    Args:
        url (str): A request's URL.

    Returns:
        int: Its bucket, from the URL's SHA-256: the same URL always lands in the same one.
    """
    return hashlib.sha256(url.encode("utf-8")).digest()[0] % _BUCKETS


def fault_for(run: int, row: Stage, index: int, url: str, attempt: int) -> Kind | None:
    """
    Which failure a request gets: a pure function, so the same run fails the same requests.

    Args:
        run (int): The run number, from 0.
        row (Stage): The stage the request belongs to.
        index (int): The request's position among the stage's requests, from 0.
        url (str): The request's URL.
        attempt (int): The attempt, from 0: the client's retries count up.

    Returns:
        Kind | None: The kind to apply, or ``None`` to forward the request. The stage's first
            request fails on its first attempt only, so the retry runs and the pass goes on; a
            URL in bucket 0 fails on every attempt, so the pass's give-up path runs, except the
            target URL outside the ``target`` stage. ``RAISES`` is raised once, on the first
            request.
    """
    kind = kind_for(run, row)
    if index == 0 and attempt == 0:
        return kind
    if kind is Kind.RAISES:
        return None
    if url == TARGET and row.name != "target":
        return None
    if _bucket(url) == 0:
        return kind
    return None
