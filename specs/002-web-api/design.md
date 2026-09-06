---
feature: Web API — persistent scans, single-user auth, queued async execution
status: done
date: 2026-09-06
related: [002-web-api/requirements.md, 001-foundation/design.md]
origin: conception
---

# 002 — Web API — Design

Traceability: every component and decision cites its requirement (`— RF-NN` / `— RNF-NN`).
Requirements: [requirements.md](requirements.md).

## Overview

`webvigil.api` is a FastAPI application that wraps the spec 001 `Orchestrator`. It adds
persistence (SQLite via SQLModel + Alembic), single-user auth (argon2 + JWT cookie), and a
one-slot async scan queue. It ships in the existing `web` extra and is served by its own
`webvigil-web` entry point.

```
                    webvigil-web serve / migrate / reset-password
                                     │
                          webvigil.api.app:create_app()
        ┌──────────────┬─────────────┼──────────────┬───────────────┐
        ▼              ▼             ▼              ▼               ▼
   routes/auth    routes/scans   routes/reports  routes/meta   ScanRunner (bg task)
   security       schemas ↕ db   reporting        registry      one RUNNING at a time
        │              │             │                              │
        └──────────────┴─────────────┴──────────────────────────────┘
                                     ▼
              webvigil.api.db  (SQLModel: User/Scan/Finding/Setting) + Alembic
                                     │
                             webvigil.core.Orchestrator   (unchanged)
```

Import direction: `webvigil.api` → engine + `webvigil.reporting`. The engine imports
nothing from `webvigil.api`, `fastapi`, `sqlmodel`, `alembic`, `pyjwt`, or `argon2` — the
`import-linter` contract is extended (RNF-01).

## Module layout

```
src/webvigil/api/
├── __init__.py
├── app.py            # create_app(), lifespan (migrate → recover → start runner), CORS     — RF-16, RF-24, RF-32
├── config.py         # WebConfig (pydantic, extra=forbid); loads [web] from TOML + env      — RF-31
├── db.py             # SQLModel models, engine factory, Session helper, WAL pragma          — RF-23, RF-25
├── security.py       # argon2 hash/verify, JWT encode/decode, current_user dep, cookies     — RF-02..RF-07
├── runner.py         # ScanRunner: single-slot queue, background loop, cancellation         — RF-09, RF-10, RF-14
├── mapping.py        # ScanCreate → ScanConfig; ScanResult ⇄ rows; rows → ScanResult        — RF-10, RF-18, RF-19
├── schemas.py        # request/response models (ScanCreate, ScanOut, FindingOut, Page[T]…)  — RF-08, RF-11..13
├── deps.py           # FastAPI dependencies: get_session, current_user, get_runner
├── cli.py            # `webvigil-web` Typer app: serve / migrate / reset-password           — RF-29
└── routes/
    ├── setup.py      # GET/POST /api/setup                                                  — RF-01
    ├── auth.py       # login / logout / me / password                                      — RF-02..06
    ├── scans.py      # create / list / get / findings / cancel / delete                    — RF-08..17
    ├── reports.py    # GET /api/scans/{id}/report                                          — RF-18
    └── meta.py       # health / checks / config defaults                                   — RF-20..22

alembic.ini                            # repo root, for the dev `alembic` command only
src/webvigil/api/migrations/            # shipped inside the package (webvigil-web works after pip install)
├── env.py                              # target_metadata = SQLModel.metadata; render_as_batch=True
├── script.py.mako
└── versions/0001_initial.py            # user, scan, finding, setting                        — RF-24, RF-25
```

> Implementation note: the migrations live **inside the package** (not a repo-root
> `alembic/`) so `run_alembic_upgrade` finds them after `pip install "webvigil[web]"`.

## Components

### WebConfig — RF-31

```python
class WebConfig(BaseModel):
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
    def load(cls, path: str | Path | None = None) -> "WebConfig": ...
```

- `load` reads `webvigil.toml` (or `--config`), takes only its `[web]` table, then applies
  env overrides: `WEBVIGIL_DATABASE_PATH`, `WEBVIGIL_WEB_HOST`, `WEBVIGIL_WEB_PORT`,
  `WEBVIGIL_SESSION_SECRET`, `WEBVIGIL_COOKIE_SECURE`, `WEBVIGIL_CORS_ORIGINS` (comma list).
- The engine's `ScanConfig` gains one ignored passthrough field so the shared file
  validates for both (ADR-3):

  ```python
  class ScanConfig(_Section):          # still extra="forbid"
      ...
      web: dict[str, Any] | None = None   # owned by webvigil.api; the engine never reads it
  ```

### Database — RF-23, RF-25

`db.py`:

```python
class ScanStatus(StrEnum):
    QUEUED = "queued"; RUNNING = "running"; COMPLETED = "completed"
    FAILED = "failed"; CANCELLED = "cancelled"; INTERRUPTED = "interrupted"

TERMINAL = {COMPLETED, FAILED, CANCELLED, INTERRUPTED}

class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    password_hash: str
    created_at: datetime
    updated_at: datetime

class Scan(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    target: str
    mode: str                      # "passive" | "active"
    scope: str                     # "host" | "subdomains"
    options: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    status: ScanStatus = Field(default=ScanStatus.QUEUED, index=True)
    authorized_by: str | None = None
    tool_version: str | None = None
    error: str | None = None
    created_at: datetime = Field(index=True)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    pages_scanned: int = 0
    counts: dict[str, int] = Field(default_factory=dict, sa_column=Column(JSON))
    check_errors: list[dict] = Field(default_factory=list, sa_column=Column(JSON))
    warnings: list[str] = Field(default_factory=list, sa_column=Column(JSON))

class Finding(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True, ondelete="CASCADE")
    check_id: str
    severity: int
    confidence: int
    title: str
    description: str
    location: dict[str, Any] = Field(sa_column=Column(JSON))
    remediation: str
    evidence: list[dict] = Field(default_factory=list, sa_column=Column(JSON))
    cwe: list[int] = Field(default_factory=list, sa_column=Column(JSON))
    references: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    fingerprint: str

class Setting(SQLModel, table=True):
    key: str = Field(primary_key=True)
    value: str
```

- `options` holds `max_pages`, `delay_ms`, `follow_robots`, `fail_on`, `disabled_checks`
  (only keys the user supplied; the runner fills gaps from `ScanConfig` defaults). `fail_on`
  is stored for display only — the API has no exit code.
- `check_errors` / `warnings` added beyond RF-25 so a stored scan round-trips losslessly to
  a `ScanResult` (RF-19).
- `create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})`; on
  connect, `PRAGMA journal_mode=WAL` and `PRAGMA foreign_keys=ON` (via a SQLAlchemy
  `connect` event).
- **Sync** sessions (ADR-1). `get_session()` dependency yields a `Session` per request;
  the runner opens short-lived sessions inside `asyncio.to_thread` helpers.
- Scan `id` is an autoincrement int — guessable, but every scan route is auth-gated.

### Security — RF-02..RF-07

`security.py`:

```python
_hasher = argon2.PasswordHasher()            # argon2id, library defaults (RNF-04)
SESSION_COOKIE = "webvigil_session"

def hash_password(pw: str) -> str: ...
def verify_password(pw: str, hashed: str) -> bool:   # False on VerifyMismatchError
def create_token(user_id: int, secret: str, ttl_hours: int) -> str    # PyJWT HS256; sub, iat, exp
def decode_token(token: str, secret: str) -> int | None               # None on any error

def set_session_cookie(resp: Response, token: str, cfg: WebConfig) -> None
def clear_session_cookie(resp: Response) -> None
```

- `set_session_cookie`: `HttpOnly`, `SameSite=lax`, `Path=/`, `Secure=cfg.cookie_secure`,
  `Max-Age=ttl`.
- `current_user` dependency: reads `SESSION_COOKIE` → `decode_token` with
  `request.app.state.session_secret` → loads the `User` → returns it, else
  `HTTPException(401, "not authenticated")`.
- **Session secret resolution** (lifespan, ADR-5): if `cfg.session_secret` is set, use it;
  else read `Setting["session_secret"]`; else generate `secrets.token_urlsafe(48)`, insert
  the row, log a warning ("generated a session signing secret; set web.session_secret to
  pin it"). Result stored on `app.state.session_secret`.
- No server-side session store; logout just clears the caller's cookie (ADR-4).

### ScanRunner — RF-09, RF-10, RF-14, RF-16

`runner.py` — one asyncio task, created in the lifespan, owns the single execution slot.

```python
class ScanRunner:
    def __init__(self, engine, *, orchestrator_factory=_default_orchestrator): ...
    async def start(self) -> None            # create_task(self._loop())
    async def stop(self) -> None             # cancel current, wake loop, await it
    def wake(self) -> None                   # self._event.set() — called after create/cancel
    async def cancel(self, scan_id: int) -> Literal["cancelled", "not_cancellable"]
    @property
    def current_scan_id(self) -> int | None
```

Loop:

```
while not stopped:
    scan_id = await to_thread(claim_next_queued)      # SELECT oldest QUEUED → UPDATE RUNNING, started_at
    if scan_id is None:
        event.clear(); await event.wait(); continue
    task = create_task(self._run_scan(scan_id))
    self._current = (scan_id, task)
    try:
        await task
    except CancelledError:
        await to_thread(mark_cancelled, scan_id)
        if stopped: raise
    finally:
        self._current = None
```

`_run_scan(scan_id)`:

```
scan   = to_thread(load_scan, scan_id)
config = build_scan_config(scan)                       # mapping.py
try:
    result = await Orchestrator(config).run(scan.target)
except CancelledError:
    raise                                              # handled by the loop
except WebVigilError as exc:
    await to_thread(mark_failed, scan_id, str(exc)); return
except Exception as exc:
    await to_thread(mark_failed, scan_id, f"internal error: {exc!r}"); return
await to_thread(store_result, scan_id, result)         # findings + counts + COMPLETED
```

- **Cancellation (ADR-7):** `cancel(scan_id)` — if it is the running scan, `task.cancel()`
  and return `"cancelled"`; if it is `QUEUED` in the DB, `UPDATE → CANCELLED`; otherwise
  `"not_cancellable"` (the route maps that to 409/404). `Orchestrator.run` wraps its work
  in `async with HttpClient(...)`, so `CancelledError` unwinds it and closes the client;
  findings are only produced at the very end, so a cancelled scan persists none.
- **Restart recovery (RF-16):** the lifespan, before `runner.start()`, runs
  `UPDATE scan SET status='interrupted', error='server restarted during scan',
  finished_at=now() WHERE status='running'`, then `runner.wake()`.
- Every DB helper (`claim_next_queued`, `store_result`, …) opens and closes its own `Session`
  inside the `to_thread` call — never held across an `await` (Risks).

### mapping.py — RF-10, RF-18, RF-19

```python
def build_scan_config(scan: Scan) -> ScanConfig:
    opts = scan.options
    overrides = {"scan": {"mode": scan.mode, "scope": scan.scope}, "http": {}, "checks": {}}
    for k in ("max_pages", "follow_robots"):
        if k in opts: overrides["scan"][k] = opts[k]
    if "delay_ms" in opts: overrides["http"]["delay_ms"] = opts["delay_ms"]
    if opts.get("disabled_checks"): overrides["checks"]["disabled"] = opts["disabled_checks"]
    if scan.mode == "active": overrides["active"] = {"authorized_by": scan.authorized_by}
    return ScanConfig().with_overrides(**overrides)

def store_result(session, scan_id, result: ScanResult) -> None    # writes Scan + Finding rows
def rows_to_result(scan: Scan, findings: list[Finding]) -> ScanResult   # inverse, for reports
```

`rows_to_result` rebuilds `ScanMetadata`, `Finding` (spec 001 model), `CheckError`, and
`warnings` so `webvigil.reporting.get_reporter(fmt).render(result)` produces the same bytes
as a live scan (RF-19). Tested by a round-trip assertion.

### FastAPI app — RF-16, RF-24, RF-32

```python
def create_app(config: WebConfig | None = None) -> FastAPI:
    cfg = config or WebConfig.load()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if cfg.auto_migrate:
            run_alembic_upgrade(cfg)                      # "alembic upgrade head"
        engine = make_engine(cfg)
        app.state.config = cfg
        app.state.engine = engine
        app.state.session_secret = resolve_session_secret(engine, cfg)
        recover_interrupted_scans(engine)                 # RF-16
        runner = ScanRunner(engine)
        app.state.runner = runner
        await runner.start()
        runner.wake()
        try:
            yield
        finally:
            await runner.stop()
            engine.dispose()

    app = FastAPI(title="WebVigil API", version=__version__, lifespan=lifespan,
                  docs_url="/docs", openapi_url="/openapi.json")
    if cfg.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=cfg.cors_origins,
                           allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
    for router in (meta.router, setup.router, auth.router, scans.router, reports.router):
        app.include_router(router, prefix="/api")
    return app

app = create_app()      # module global, for `uvicorn webvigil.api.app:app`
```

### webvigil-web CLI — RF-29

`cli.py` — a small Typer app, `[project.scripts] webvigil-web = "webvigil.api.cli:main"`:

| Command | Action |
|---|---|
| `webvigil-web serve [--host --port --reload]` | `uvicorn.run("webvigil.api.app:app", ...)` using `WebConfig` for defaults |
| `webvigil-web migrate` | `alembic upgrade head` against the configured DB |
| `webvigil-web reset-password [--username U]` | prompt for a new password, re-hash, update the row (fallback to the setup screen) |

## Interfaces

All routes are under `/api`. `Auth` column: **none** = public, **session** = valid cookie
required (RF-05).

| Method | Path | Auth | Body → Response | Codes |
|---|---|---|---|---|
| GET | `/health` | none | → `{status, version}` | 200 |
| GET | `/setup` | none | → `{needs_setup: bool}` | 200 |
| POST | `/setup` | none | `{username, password}` → `UserOut` | 201, 409, 422 |
| POST | `/auth/login` | none | `{username, password}` → *204 + Set-Cookie* | 204, 401, 422 |
| POST | `/auth/logout` | session | → *204 + clear cookie* | 204 |
| GET | `/auth/me` | session | → `UserOut` | 200, 401 |
| POST | `/auth/password` | session | `{current_password, new_password}` → 204 | 204, 403, 422 |
| GET | `/checks` | session | → `list[CheckOut]` | 200 |
| GET | `/config/defaults` | session | → `ScanDefaults` | 200 |
| POST | `/scans` | session | `ScanCreate` → `ScanOut` | 201, 422 |
| GET | `/scans` | session | `?status=&limit=&cursor=` → `Page[ScanSummary]` | 200 |
| GET | `/scans/{id}` | session | → `ScanOut` | 200, 404 |
| GET | `/scans/{id}/findings` | session | `?severity=&check_id=` → `list[FindingOut]` | 200, 404 |
| POST | `/scans/{id}/cancel` | session | → 204 | 204, 404, 409 |
| DELETE | `/scans/{id}` | session | → 204 | 204, 404, 409 |
| GET | `/scans/{id}/report` | session | `?format=json\|sarif\|html\|md&download=true` → *file* | 200, 404, 409, 422 |

`cancel` and `POST /scans` route handlers are `async def` (they touch the runner, which
lives on the event loop); pure-DB read routes are `def` (threadpool) — ADR-1, Risks.

### Schemas (`schemas.py`)

```python
class ScanCreate(BaseModel):
    target: str
    mode: ScanMode = ScanMode.PASSIVE
    scope: Scope = Scope.HOST
    max_pages: int | None = Field(default=None, gt=0)
    delay_ms: int | None = Field(default=None, ge=0)
    follow_robots: bool | None = None
    authorized_by: str | None = None
    fail_on: FailOn | None = None
    disabled_checks: list[str] = []

    @model_validator(mode="after")
    def _active_needs_authorization(self):
        if self.mode is ScanMode.ACTIVE and not (self.authorized_by or "").strip():
            raise ValueError("authorized_by is required for an active scan")
        # also: Target.parse(self.target) to reject bad URLs early -> ValueError -> 422
        return self

class ScanSummary(BaseModel):   # list view
    id: int; target: str; mode: ScanMode; scope: Scope; status: ScanStatus
    counts: dict[str, int]; created_at: datetime
    started_at: datetime | None; finished_at: datetime | None

class ScanOut(ScanSummary):     # detail view
    authorized_by: str | None; tool_version: str | None; error: str | None
    pages_scanned: int; options: dict[str, Any]

class FindingOut(BaseModel):    # mirrors webvigil.core.Finding
    check_id: str; severity: str; confidence: str; title: str; description: str
    location: LocationOut; remediation: str; evidence: list[EvidenceOut]
    cwe: list[int]; references: list[str]; fingerprint: str

class Page(BaseModel, Generic[T]):
    items: list[T]; next_cursor: str | None
```

- `severity` / `confidence` are serialized as their names (`"HIGH"`) for the UI, matching
  the JSON reporter.
- Cursor: base64 of `f"{created_at.isoformat()}|{id}"`; `list` orders by
  `created_at DESC, id DESC` and filters `(created_at, id) < cursor` (ADR — decision 6).

## ADRs

### ADR-1 — Sync SQLModel sessions; async confined to the runner
**Decision:** SQLModel/SQLAlchemy **sync** sessions. Read-only routes are `def` (Starlette
threadpool). The `ScanRunner` is `async` (it awaits `Orchestrator.run`) and does its DB
writes inside `asyncio.to_thread` helpers that open and close their own session.
**Alternatives:** async SQLAlchemy + `aiosqlite`; a sync runner in a thread.
**Why:** no new dependency, matches the SQLModel/FastAPI documentation, and the endpoints
are trivial queries. The runner is the only place that mixes DB + `await`, and it is
isolated.
**Trade-off:** the runner must never hold a `Session` across an `await`; `cancel` / `create`
routes must be `async def` to talk to the loop-resident runner safely.

### ADR-2 — One background `ScanRunner`, single execution slot
**Decision:** exactly one scan `RUNNING`; the rest `QUEUED`, started oldest-first.
**Alternatives:** a small worker pool; an external queue (`arq` + Redis).
**Why:** decision with Ryan; single-user, one machine, and the engine already parallelises
*within* a scan. Predictable load.
**Trade-off:** throughput of one scan at a time. A migration note to `arq` is recorded for
when the API grows past single-user.

### ADR-3 — `ScanConfig` gets an ignored `web` passthrough field
**Decision:** add `web: dict | None = None` to `webvigil.core.config.ScanConfig` (kept
`extra="forbid"` otherwise). The CLI/engine never read it; `webvigil.api` parses `[web]`
into its own strict `WebConfig`.
**Alternatives:** a separate `webvigil-web.toml`; relax `ScanConfig` to `extra="ignore"`.
**Why:** one `webvigil.toml` for both tools, while section-level typos (`[scna]`,
`max_page`) stay hard errors for the CLI.
**Trade-off:** the engine model carries one field it ignores; a `[web]` typo is only caught
by the API, not the CLI.

### ADR-4 — Stateless JWT cookie, no server-side session store
**Decision:** the session is a signed JWT in an httpOnly cookie; there is no session table
and no revocation list.
**Alternatives:** a `session` table with server-side invalidation; opaque tokens.
**Why:** decision with Ryan; a local single-user tool. Logout clears the caller's cookie;
a short TTL (12h default) bounds exposure.
**Trade-off:** a leaked cookie is valid until it expires; "log out everywhere" is not
possible without rotating `web.session_secret`.

### ADR-5 — Generate and persist the session secret when unset
**Decision:** if `web.session_secret` is unset, generate one and store it in a `setting`
row; reuse it on later starts.
**Alternatives:** refuse to start without a secret.
**Why:** zero-config first run, and sessions survive restarts.
**Trade-off:** the secret lives in the SQLite file — the same trust boundary as the
password hash. Documented; setting `web.session_secret` explicitly is recommended for
shared deployments.

### ADR-6 — Three model layers: engine ⟷ DB ⟷ wire
**Decision:** `webvigil.core.*` (engine), `webvigil.api.db.*` (SQLModel tables with JSON
columns for nested data), and `webvigil.api.schemas.*` (request/response) are separate;
`mapping.py` converts between them.
**Alternatives:** persist `ScanResult` as one JSON blob; expose SQLModel rows directly.
**Why:** findings must be queryable (filter by severity / check id — RF-13), the wire shape
serves the UI (severity as a name), and the three shapes evolve independently.
**Trade-off:** explicit mapping code and a round-trip test to keep them in sync.

### ADR-7 — Cancellation by `Task.cancel()` only
**Decision:** cancelling a `RUNNING` scan cancels its `asyncio.Task`; no cancellation hook
is added to `Orchestrator.run`.
**Alternatives:** a cooperative cancel token threaded through the engine.
**Why:** decision with Ryan. `Orchestrator.run` already wraps its work in
`async with HttpClient(...)`, so `CancelledError` unwinds cleanly and closes the client, and
findings are only produced at the end — a cancelled scan persists nothing partial.
**Trade-off:** a check stuck in a long non-`await` computation would delay cancellation
(none of the v0.1 checks do this).

### ADR-8 — Alembic from the first migration; `create_all` is never used
**Decision:** ship `alembic/` with an initial migration; tests and startup run
`upgrade head`. `SQLModel.metadata.create_all` is not called anywhere.
**Alternatives:** `create_all` now, adopt Alembic when the schema first changes.
**Why:** decision with Ryan; the schema will change in spec 003+ and a retrofit is painful.
**Trade-off:** more setup now; `env.py` needs `render_as_batch=True` for SQLite's limited
`ALTER TABLE`.

### ADR-9 — `webvigil-web` as its own console script
**Decision:** a separate `webvigil-web` entry point, declared by the `web` extra.
**Alternatives:** a `webvigil web ...` subcommand group on the main CLI.
**Why:** `pip install webvigil` (no extra) must not import FastAPI/uvicorn; keeping the web
commands in a separate script declared by `[project.optional-dependencies].web` enforces
that.
**Trade-off:** two commands (`webvigil`, `webvigil-web`).

## Impact

- **New:** `src/webvigil/api/**`, `alembic/**`, `alembic.ini`, `docker-compose.yml`,
  `docs/web-api.md`.
- **`pyproject.toml`:** `[project.scripts]` gains `webvigil-web = "webvigil.api.cli:main"`;
  no new dependencies (the `web` extra already pins `fastapi`, `uvicorn`, `sqlmodel`,
  `alembic`, `argon2-cffi`, `pyjwt`, `python-multipart`). `[tool.importlinter]` gets the
  extended contract. `[tool.mypy].files` already covers `src/webvigil/api`.
- **`webvigil.core.config`:** the one-line `web` passthrough field (ADR-3) + a test.
- **`webvigil.example.toml`:** a `[web]` section.
- **CI:** the `quality` job already runs `uv sync --all-extras`, so the API tests and
  `mypy` cover the new package. Add an Alembic round-trip (`upgrade head` → `downgrade
  base`) to the test suite.
- **README / CLAUDE / architecture.md:** a "Web API" section; `webvigil.api` moves from
  "spec 002" to implemented.
- **Docker:** `docker-compose.yml` runs `webvigil-web serve` with a named volume for the
  SQLite file; the existing CLI `Dockerfile` is unchanged (no web extra).

## Risks

| Risk | Mitigation |
|---|---|
| A `Session` held across an `await` in the runner (classic SQLAlchemy misuse). | Every runner DB helper opens/closes its own session inside one `to_thread` call; a review checklist item and a test that runs a full scan through the runner. |
| SQLite write/read contention between the runner and endpoints. | `PRAGMA journal_mode=WAL`; the single-slot runner means at most one writer; endpoints are short reads. |
| `Task.cancel()` from a threadpool route thread is unsafe. | `cancel` and `create` routes are `async def` (run on the loop); they call `runner.cancel()` / `runner.wake()` directly. |
| `create_app()` at import time runs `WebConfig.load()` + migrations. | A malformed config fails the import with a clear pydantic error; `webvigil-web serve` surfaces it. Migrations are idempotent. |
| Active Mode is easier to trigger from a form than from a CLI flag. | RF-08 still requires `authorized_by`; it is stored and printed in every report; `SECURITY.md` gains a note that the API can start Active scans. |
| The session secret and password hash share the SQLite file. | Documented in `docs/web-api.md`; `web.session_secret` can be pinned outside the DB; the file is the single backup unit. |
| SQLite `ALTER TABLE` limits break a future migration. | `render_as_batch=True` in `env.py` from the first migration. |
| A crash loses an in-flight scan with no partial result. | RF-16 marks it `INTERRUPTED` with a note; re-running is cheap. Acceptable for a local tool. |

## Testing — RNF-02, RNF-03

- **Fixtures:** a `client` fixture = `TestClient(create_app(WebConfig(database_path=tmp)))`
  with `auto_migrate` on; a `logged_in_client` that runs setup + login; the runner's
  `orchestrator_factory` is overridden to point `Orchestrator` at the spec 001 Starlette
  fixture app via the `transport` seam (no network).
- **Auth:** `needs_setup` toggles; second `POST /setup` → 409; login sets the cookie; bad
  credentials → 401; a protected route without a cookie → 401; `/auth/me`; password change
  (wrong current → 403); an expired token → 401 (short `session_ttl`).
- **Scan lifecycle:** create validates (`ftp://` → 422, `active` without `authorized_by` →
  422); create → `QUEUED` → runner → `COMPLETED` with findings; a second scan stays
  `QUEUED` while the first is `RUNNING`; cancel `QUEUED` → `CANCELLED`; cancel `RUNNING` →
  `CANCELLED` and **zero** findings persisted; delete terminal → 204, delete `RUNNING` →
  409; list pagination (cursor) and `status` filter; findings `severity` / `check_id`
  filter and deterministic order.
- **Restart recovery:** insert a `RUNNING` row, start a fresh app, assert it becomes
  `INTERRUPTED` and the queue resumes.
- **Reports:** each format downloads with the right `Content-Type` and
  `Content-Disposition`; `?download=false` → `inline`; `json` byte-identical to
  `get_reporter("json").render(rows_to_result(...))`; report on a `QUEUED` scan → 409.
- **Round-trip:** `store_result` then `rows_to_result` equals the original `ScanResult`.
- **Meta:** `/health` needs no auth; `/checks` matches the registry; `/config/defaults`
  matches `ScanConfig()`.
- **Migrations:** `alembic upgrade head` then `downgrade base` on a tmp DB; a metadata-diff
  check that the models match `0001_initial`.
- **Config:** a `webvigil.toml` with a `[web]` section still loads under `ScanConfig.load`;
  `WebConfig` rejects an unknown `[web]` key.
- **import-linter:** the extended contract holds (engine ✗ fastapi/sqlmodel/alembic/api).
- **Gate:** `/qualidade-python` + `uv run lint-imports` green.

## Open questions

None blocking. Deferred to implementation: exact argon2 parameters (start from library
defaults), the `docker-compose.yml` port and volume names, and whether `webvigil-web serve`
should default `--reload` off in a container (yes).
