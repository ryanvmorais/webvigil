---
feature: Web API — persistent scans, single-user auth, queued async execution
status: done
date: 2026-09-06
related: [001-foundation/requirements.md]
origin: conception
---

# 002 — Web API

## Context and problem

Spec 001 shipped the scan engine and the CLI. Everything is one-shot: you run `webvigil
scan`, read the report, and it's gone. There is no history, no way to trigger a scan from a
browser, and no persistent store a dashboard could read.

This spec adds a **local-first Web API** (`webvigil.api`, FastAPI) on top of the same
`Orchestrator`. It is single-user, backed by SQLite, and runs scans as in-process async
tasks with a one-at-a-time queue. It exposes REST endpoints to authenticate, trigger and
inspect scans, list findings, and download reports in the four existing formats.

The Next.js dashboard that consumes this API is **spec 003** — this spec is the API only.

### Where it sits

```
webvigil.cli          webvigil.api  (FastAPI, `web` extra) ── spec 003 UI talks only to this
      \                    │
       \                   ├── webvigil.api.db     (SQLModel models + Alembic)  [API-only]
        \                  │
         └──────────────► webvigil.core.Orchestrator  (unchanged)
```

`webvigil.api` imports the engine. The engine still imports nothing from `webvigil.api`,
`fastapi`, `sqlmodel`, or `alembic` — the `import-linter` contract is extended to cover this.

## Goals

- A FastAPI app installable via `pip install "webvigil[web]"`, served by uvicorn.
- **First-run setup** then username + password login; the session is a signed, httpOnly
  JWT cookie; passwords are argon2id hashes.
- **SQLite persistence** (SQLModel + Alembic from day one) of `Scan` records and their
  `Finding`s.
- **Queued async execution**: at most one scan `RUNNING`, the rest `QUEUED`; scans left
  `RUNNING` when the process dies are marked `INTERRUPTED` on the next start.
- REST endpoints for auth, scans (create / list / get / cancel / delete), findings, report
  download (json / sarif / html / md), the check catalogue, and health.
- The engine's Safe-Mode default, Active-Mode authorization gate, and good-neighbor policy
  apply unchanged — the API passes options straight through.
- OpenAPI docs at `/docs`.
- A `webvigil-web` entry point for serving and for database/admin tasks.

## Non-goals

- Any frontend — the Next.js dashboard is **spec 003**.
- Multi-user, roles, teams, organisations, or per-user data isolation.
- Databases other than SQLite (the connection string is swappable later; not now).
- External workers / brokers (`arq`, Celery, Redis). A migration note is recorded for when
  concurrency demands it.
- Scheduled or recurring scans, notifications, webhooks, email.
- API tokens or any non-cookie auth mechanism.
- Real-time scan-progress streaming (WebSocket / SSE) — clients poll in 002.
- Comparing or diffing scans over time.
- TLS termination, API rate limiting, request-size limits beyond FastAPI defaults — a
  reverse proxy's job.
- New checks or engine features — this spec adds no scanning capability.

## Personas

| Persona | Needs from 002 |
|---|---|
| **Solo dev / small-team lead** | Run WebVigil on a laptop or an internal box and keep a browsable history of scans and findings instead of re-running the CLI and losing output. (Uses it through the spec 003 UI.) |
| **Frontend developer (spec 003)** | A stable, documented REST contract: predictable scan status transitions, consistent error shapes, deterministic finding ordering, and a way to preview and download reports. |
| **Automation / CI** | Secondary in 002 — could `POST` a scan and poll, but SARIF-in-CI is already covered by the CLI. |

## Functional requirements

### Authentication and first-run setup

**RF-01 — First-run setup**
- **Given** the database has no user, **when** `GET /api/setup` is called, **then** it
  returns `{ "needs_setup": true }` (unauthenticated).
- **Given** no user exists, **when** `POST /api/setup` is called with a username and a
  password meeting the policy (min length, not empty), **then** the single user is created
  with an argon2id password hash and the response is 201.
- **Given** a user already exists, **when** `POST /api/setup` is called, **then** it
  returns 409 and creates nothing.

**RF-02 — Login**
- **Given** valid credentials, **when** `POST /api/auth/login` is called, **then** the
  response sets a `webvigil_session` cookie: `HttpOnly`, `SameSite=Lax`, `Path=/`,
  `Secure` when `web.cookie_secure` is true, containing a signed JWT with a bounded
  lifetime (`web.session_ttl`, default 12h).
- **Given** a wrong username or password, **when** login is called, **then** it returns 401
  with a generic message ("invalid username or password") and no cookie. Verification uses
  argon2's constant-time check.

**RF-03 — Logout**
- **Given** any request, **when** `POST /api/auth/logout` is called, **then** the session
  cookie is cleared. (Stateless JWT: this clears the caller's cookie only.)

**RF-04 — Session identity**
- **Given** a valid, unexpired session cookie, **when** `GET /api/auth/me` is called,
  **then** it returns `{ id, username, created_at }`.
- **Given** a missing, malformed, or expired cookie, **when** `GET /api/auth/me` is called,
  **then** it returns 401.

**RF-05 — Route protection**
- **Given** no valid session, **when** any `/api/*` route is called except
  `/api/setup`, `/api/auth/login`, and `/api/health`, **then** it returns 401.

**RF-06 — Password change**
- **Given** an authenticated user, **when** `POST /api/auth/password` is called with the
  correct current password and a new one, **then** the hash is replaced and existing
  cookies keep working until they expire (no forced re-login in 002).
- **Given** a wrong current password, **then** it returns 403.

**RF-07 — Session signing secret**
- **Given** `web.session_secret` is set (config or env), **when** the server starts, **then**
  it uses that value to sign and verify JWTs.
- **Given** it is unset, **when** the server starts, **then** it generates a random secret,
  persists it to a `setting` row, logs a warning, and reuses it on later starts (so sessions
  survive restarts).

### Scans

**RF-08 — Create a scan**
- **Given** an authenticated request, **when** `POST /api/scans` is called with
  `{ target, mode?, scope?, max_pages?, delay_ms?, follow_robots?, authorized_by?, fail_on?, disabled_checks? }`,
  **then** the payload is validated with the same rules as the engine's `ScanConfig`
  (invalid target, unknown enum, etc. → 422), a `Scan` row is created with status
  `QUEUED`, and the created scan is returned with 201.
- **Given** `mode = "active"` without a non-empty `authorized_by`, **when** create is
  called, **then** it returns 422 and creates nothing.
- **Given** no `mode`, **then** the scan defaults to `passive`.

**RF-09 — Queue semantics (one at a time)**
- **Given** the runner is idle and a scan is created, **when** the request returns, **then**
  that scan transitions to `RUNNING` shortly after (the runner picks it up).
- **Given** a scan is already `RUNNING` and another is created, **when** the request
  returns, **then** the new scan stays `QUEUED`.
- **Given** a scan reaches a terminal state, **when** the runner is freed, **then** the
  oldest `QUEUED` scan (by `created_at`) starts next.

**RF-10 — Execution**
- **Given** a `QUEUED` scan the runner picks up, **when** it runs, **then** the runner
  builds a `ScanConfig` from the row and calls `Orchestrator(config).run(target)`.
- **Given** the run completes, **then** the scan's findings, per-severity counts,
  `pages_scanned`, `tool_version`, `started_at`/`finished_at` are stored and the status
  becomes `COMPLETED`.
- **Given** the engine raises a `WebVigilError` (bad target, unreachable, config), **then**
  the status becomes `FAILED` and `error` holds the message; the runner moves on.

**RF-11 — List scans**
- **Given** `GET /api/scans?status=&limit=&cursor=`, **when** called, **then** it returns a
  page of scan summaries (`id, target, mode, scope, status, counts, created_at,
  started_at, finished_at`), newest first, with an opaque `next_cursor` when more remain.
- `limit` defaults to 20, caps at 100.

**RF-12 — Get one scan**
- **Given** `GET /api/scans/{id}`, **when** the scan exists, **then** it returns the full
  record (everything from the summary plus `authorized_by`, `options`, `error`,
  `pages_scanned`, `tool_version`) but **not** the findings array.
- **Given** the id does not exist, **then** 404.

**RF-13 — List a scan's findings**
- **Given** `GET /api/scans/{id}/findings?severity=&check_id=`, **when** called, **then** it
  returns the scan's findings (full `Finding` shape from spec 001), filtered by the given
  `severity` (at-or-above) and/or `check_id`, ordered deterministically: severity
  descending, then `check_id`, `location.url`, `location.key` — the same order the reporters
  use.

**RF-14 — Cancel a scan**
- **Given** a `QUEUED` scan, **when** `POST /api/scans/{id}/cancel` is called, **then** it
  becomes `CANCELLED` and never runs.
- **Given** a `RUNNING` scan, **when** cancel is called, **then** the running asyncio task
  is cancelled, the engine's `HttpClient` is closed, no partial findings are persisted, and
  the status becomes `CANCELLED`.
- **Given** a scan in a terminal state (`COMPLETED`/`FAILED`/`CANCELLED`/`INTERRUPTED`),
  **then** cancel returns 409.

**RF-15 — Delete a scan**
- **Given** a scan in a terminal state, **when** `DELETE /api/scans/{id}` is called, **then**
  the scan row and all its findings are removed and the response is 204.
- **Given** a `QUEUED` or `RUNNING` scan, **then** delete returns 409 (cancel it first).

**RF-16 — Restart recovery**
- **Given** the process restarts, **when** the app starts up, **then** every scan still
  marked `RUNNING` is set to `INTERRUPTED` (with an `error` note), and the runner resumes
  by picking up the remaining `QUEUED` scans.

**RF-17 — Status model**
- The status of a scan is one of `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`,
  `INTERRUPTED`. Transitions: `QUEUED → RUNNING → {COMPLETED | FAILED | CANCELLED |
  INTERRUPTED}`, and `QUEUED → CANCELLED`. The value is present in every scan payload and
  documented in the OpenAPI schema.

### Reports

**RF-18 — Download a report**
- **Given** `GET /api/scans/{id}/report?format=json|sarif|html|md`, **when** the scan is in
  a state that has results (`COMPLETED` or `INTERRUPTED` with partial data), **then** the
  stored result is rebuilt into a `ScanResult` and rendered via
  `webvigil.reporting.get_reporter(format)`, returned with the correct `Content-Type` and
  `Content-Disposition: attachment; filename="webvigil-<id>.<ext>"`.
- **Given** `?download=false`, **then** `Content-Disposition: inline` (so the UI can preview
  HTML without a download prompt).
- **Given** a scan with no results yet (`QUEUED`/`RUNNING`/`FAILED`/`CANCELLED`), **then**
  409.
- The `json` output is byte-identical to what the CLI produces for the same `ScanResult`.

**RF-19 — Lossless persistence**
- The data stored for a scan round-trips to a `ScanResult` such that all four reporters
  produce the same output they would from a live scan (mirrors RF-21 of spec 001).

### Catalogue and meta

**RF-20 — Check catalogue**
- **Given** `GET /api/checks`, **when** called, **then** it returns every registered check
  (`id, name, category, mode, default_severity, cwe, references`) — the same data as
  `webvigil list-checks`.

**RF-21 — Health**
- **Given** `GET /api/health`, **when** called (no auth), **then** it returns
  `{ "status": "ok", "version": "<tool version>" }` with 200.

**RF-22 — Scan-form defaults**
- **Given** `GET /api/config/defaults`, **when** called, **then** it returns the default
  `ScanConfig` values (mode, scope, max_pages, delay_ms, follow_robots, fail_on) so the
  spec 003 form can pre-fill.

### Persistence

**RF-23 — SQLite store**
- The database is SQLite via SQLModel. The file path comes from `web.database_path`
  (config) or `WEBVIGIL_DATABASE_PATH` (env), default `./webvigil.db`. The file and its
  parent directory are created on first start.

**RF-24 — Alembic migrations**
- The repo carries an `alembic/` directory and `alembic.ini` (scoped to the API).
- `webvigil-web migrate` runs `alembic upgrade head`. The server runs the same on startup
  unless `web.auto_migrate = false`.
- The initial migration creates `user`, `scan`, `finding`, and `setting`.

**RF-25 — Schema**

| Table | Columns (essentials) |
|---|---|
| `user` | `id`, `username` (unique), `password_hash`, `created_at`, `updated_at` |
| `scan` | `id`, `target`, `mode`, `scope`, `options` (json: max_pages, delay_ms, follow_robots, fail_on, disabled_checks), `status`, `authorized_by` (nullable), `tool_version`, `error` (nullable), `created_at`, `started_at` (nullable), `finished_at` (nullable), `pages_scanned`, `counts` (json) |
| `finding` | `id`, `scan_id` (fk → scan, cascade delete), `check_id`, `severity`, `confidence`, `title`, `description`, `location` (json), `remediation`, `evidence` (json), `cwe` (json), `references` (json), `fingerprint` |
| `setting` | `key` (pk), `value` — holds the generated session secret and similar single values |

### Engine integration and safety

**RF-26 — Thin client of the orchestrator**
- The API must not reimplement crawling, checks, or reporting. It builds a `ScanConfig`,
  calls `Orchestrator.run`, stores the `ScanResult`, and renders reports with
  `webvigil.reporting`.

**RF-27 — Active-Mode gate is the engine's**
- The API passes `authorized_by` straight to the `ScanConfig`. If the engine raises
  `ActiveModeNotAuthorized` (it should not, given RF-08's validation, but as a backstop),
  the API surfaces it as 422 and marks the scan `FAILED`.
- The authorization text is stored on the `scan` row and appears in every report.

**RF-28 — Good-neighbor policy unchanged**
- Because only one scan runs at a time (RF-09), the engine's concurrency cap, delay, page
  limit, and scope guard apply per scan exactly as in spec 001.

### Operations

**RF-29 — Web entry point**
- A `webvigil-web` console script (declared by the `web` extra) with:
  `webvigil-web serve [--host --port --reload]`, `webvigil-web migrate`,
  `webvigil-web reset-password [--username]` (interactive password prompt; a fallback to
  the first-run setup screen).

**RF-30 — Container**
- A `docker-compose.yml` (or a second Dockerfile target) runs the API with uvicorn and a
  named volume for the SQLite file. `docker compose up` serves the API on a documented port.

**RF-31 — Config**
- `webvigil.example.toml` gains a `[web]` section: `database_path`, `host`, `port`,
  `session_secret`, `session_ttl`, `cookie_secure`, `auto_migrate`, `cors_origins`. These
  keys are API-only and rejected by the engine/CLI config model (which stays `extra=forbid`),
  so `[web]` lives in a separate `WebConfig` model the API loads.

**RF-32 — CORS**
- `web.cors_origins` (list, default empty) configures the allowed browser origins for the
  spec 003 dev server. Empty means same-origin only. Credentials (the cookie) are allowed
  only for the listed origins.

## Non-functional requirements

**RNF-01 — Engine purity preserved**
`webvigil.{core,http,crawler,checks,reporting}` must not import `fastapi`, `sqlmodel`,
`alembic`, `pyjwt`, `argon2`, or `webvigil.api`. The `import-linter` contract is extended;
`webvigil.api` and `webvigil.cli` may import the engine, not each other.

**RNF-02 — Quality gate**
`ruff → black → mypy (strict) → import-linter → pytest` all green. `mypy` is extended to
type-check `webvigil.api`. New runtime deps come only from the existing `web` extra
(`fastapi`, `uvicorn`, `sqlmodel`, `alembic`, `argon2-cffi`, `pyjwt`, `python-multipart`).

**RNF-03 — Tests without a network or a real server**
API tests use FastAPI's `TestClient` against a fresh SQLite database per test (tmp file or
`:memory:`). Scan execution is tested with the `Orchestrator` pointed at the spec 001
Starlette fixture app (via the `transport` seam), or with a stubbed runner — never real
egress.

**RNF-04 — Password handling**
argon2id with parameters at or above the argon2-cffi defaults. Password hashes are never
logged and never appear in any response body.

**RNF-05 — Stateful surface is small and documented**
The SQLite file and the generated session secret (a `setting` row inside it) are the only
persistent state. Backup = copy the file. Documented in `docs/`.

**RNF-06 — Consistent errors**
All error responses use FastAPI's `{ "detail": ... }` shape with a correct HTTP status.
Validation errors keep FastAPI's 422 body.

**RNF-07 — Python support**
Runs on CPython 3.12 and 3.13 (same CI matrix).

**RNF-08 — Safe by default**
`POST /api/scans` with no `mode` creates a `passive` scan. The API never escalates a scan
to active on its own and never runs a scan the user did not create.

## Resolved decisions

Settled with Ryan on 2026-09-06:

1. **Web CLI (RF-29):** a separate `webvigil-web` console script, declared by the `web`
   extra — the core `webvigil` CLI stays free of the web dependencies.
2. **Session secret when unset (RF-07):** generate a random secret, persist it to a
   `setting` row, reuse it — sessions survive restarts.
3. **Cancelling a `RUNNING` scan (RF-14):** cancelling the `asyncio.Task` and closing the
   `HttpClient` is enough for 002. No cancellation hook is added to `Orchestrator.run`; the
   design just has to ensure nothing partial is persisted when `CancelledError` propagates.
4. **`authorized_by` (RF-08):** same as the CLI — free text, stored on the scan, shown in
   every report. No extra confirmation step in the API.
5. **Evidence storage (RF-25):** store the `evidence` blobs verbatim; the engine already
   caps each item at 4 KiB, so no extra DB-layer trimming.
6. **Pagination (RF-11):** opaque cursor over `(created_at, id)`.
7. **Report preview (RF-18):** the `?download=false` toggle (`Content-Disposition: inline`)
   is enough for the spec 003 UI. No dedicated preview endpoint.
8. **Concurrent sessions:** accept stateless JWT with no server-side revocation — multiple
   valid cookies at once is fine for a local single-user tool. No token denylist.
9. **Persistence module:** `webvigil.api.db` (SQLModel models + the session/engine setup);
   Alembic config under `alembic/` at the repo root, scoped to the API.

## Open questions

None. Ready for `/spec design`.
