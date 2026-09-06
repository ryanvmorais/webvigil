---
feature: Web API — persistent scans, single-user auth, queued async execution
status: done
date: 2026-09-06
related: [002-web-api/requirements.md, 002-web-api/design.md]
origin: conception
---

# 002 — Web API — Tasks

Ordered, small tasks grouped by stage. Each references the requirement(s) it satisfies.
The last task of every stage is a quality gate (`/qualidade-python` +
`uv run lint-imports`). Work top to bottom; mark `[x]` after each. Write failing tests
first where it pays (mapping, runner, routes).

All new code lives in `src/webvigil/api/**` and `alembic/**`; no engine behaviour changes
except the one passthrough field in Stage 0.

---

## Stage 0 — Scaffolding and config

- [x] `pyproject.toml`: add `webvigil-web = "webvigil.api.cli:main"` to `[project.scripts]`;
  extend the `[tool.importlinter]` contract so `webvigil.{core,http,crawler,checks,reporting}`
  and `webvigil.cli` may not import `fastapi`, `sqlmodel`, `alembic`, `pyjwt`, `argon2`,
  or `webvigil.api`. — RNF-01, ADR-9
- [x] `webvigil.core.config.ScanConfig`: add `web: dict[str, Any] | None = None` (ignored
  passthrough) so a shared `webvigil.toml` with a `[web]` section still validates; test
  that `ScanConfig.load` tolerates `[web]` and still rejects `[scna]`. — ADR-3
- [x] Create the `webvigil.api` package skeleton (empty modules + docstrings) per the
  design layout: `app / config / db / security / runner / mapping / schemas / deps / cli`
  and `routes/{setup,auth,scans,reports,meta}.py`. — design §"Module layout"
- [x] `webvigil/api/config.py`: `WebConfig` (pydantic `extra="forbid"`) + `load(path)` that
  reads only `[web]` from the TOML and applies the `WEBVIGIL_*` env overrides. — RF-31
- [x] `webvigil.example.toml`: add a documented `[web]` section (database_path, host, port,
  session_secret, session_ttl_hours, cookie_secure, auto_migrate, cors_origins). — RF-31
- [x] Tests: `WebConfig` defaults, TOML load, env overrides, unknown `[web]` key rejected. — RF-31
- [x] Quality gate.

## Stage 1 — Database layer

- [x] `webvigil/api/db.py`: `ScanStatus` (StrEnum) + `TERMINAL`; SQLModel tables `User`,
  `Scan`, `Finding` (JSON columns for `options`/`counts`/`location`/`evidence`/`cwe`/
  `references`/`check_errors`/`warnings`), `Setting`. — RF-25
- [x] `webvigil/api/db.py`: `make_engine(config)` (`sqlite:///…`, `check_same_thread=False`)
  with a `connect` event issuing `PRAGMA journal_mode=WAL` and `PRAGMA foreign_keys=ON`;
  `session_scope()` / `get_session` helpers. — RF-23, Risks
- [x] `alembic.ini` + `alembic/env.py`: `target_metadata = SQLModel.metadata`,
  `render_as_batch=True`, URL from `WebConfig`. — RF-24, ADR-8
- [x] `alembic/versions/0001_initial.py`: create `user`, `scan`, `finding` (fk + cascade),
  `setting`; matching downgrade. — RF-24, RF-25
- [x] `webvigil/api/db.py`: `run_alembic_upgrade(config)` wrapper (`alembic upgrade head`). — RF-24
- [x] Tests: `upgrade head` then `downgrade base` on a tmp DB; a metadata-diff check that the
  models match `0001_initial`; WAL + foreign-key pragmas are active. — RF-24
- [x] Quality gate.

## Stage 2 — Security and dependencies

- [x] `webvigil/api/security.py`: `hash_password` / `verify_password` (argon2id, library
  defaults), `create_token` / `decode_token` (PyJWT HS256, `sub`/`iat`/`exp`),
  `set_session_cookie` / `clear_session_cookie` (`HttpOnly`, `SameSite=lax`, `Secure` from
  config). — RF-02, RF-03, RF-04, RNF-04
- [x] `webvigil/api/security.py`: `resolve_session_secret(engine, config)` — use
  `config.session_secret`, else the `setting` row, else generate + persist + log a warning. — RF-07, ADR-5
- [x] `webvigil/api/deps.py`: `get_session`, `get_runner`, and `current_user` (reads the
  cookie, decodes with `request.app.state.session_secret`, loads the `User`, else 401). — RF-04, RF-05
- [x] Tests: password hash round-trip and mismatch; token expiry → `decode_token` returns
  `None`; `current_user` 401 on missing/invalid/expired cookie; `resolve_session_secret`
  generate-and-reuse. — RF-04, RF-07
- [x] Quality gate.

## Stage 3 — Auth, setup and meta routes

- [x] `webvigil/api/schemas.py` (part 1): `UserOut`, `SetupIn`, `LoginIn`,
  `PasswordChangeIn`, `HealthOut`, `CheckOut`, `ScanDefaults`.
- [x] `webvigil/api/app.py`: `create_app(config)` with a minimal lifespan (engine +
  `session_secret` on `app.state`, no runner yet) and router registration under `/api`. — RF-05
- [x] `webvigil/api/routes/setup.py`: `GET /api/setup` (`needs_setup`), `POST /api/setup`
  (create the single user, 409 if one exists). — RF-01
- [x] `webvigil/api/routes/auth.py`: `login` (cookie or 401), `logout`, `me`,
  `password` (403 on wrong current). — RF-02, RF-03, RF-04, RF-06
- [x] `webvigil/api/routes/meta.py`: `GET /api/health` (no auth), `GET /api/checks`
  (from the registry, `load_plugins()` first), `GET /api/config/defaults`. — RF-20, RF-21, RF-22
- [x] Tests (`TestClient`, tmp DB): setup toggles + 409; login sets cookie, bad creds 401;
  protected route 401 without cookie; `/me`; password change; expired token → 401; `/health`
  needs no auth; `/checks` matches the registry. — RF-01..06, RF-20, RF-21
- [x] Quality gate.

## Stage 4 — Scan runner

- [x] `webvigil/api/mapping.py`: `build_scan_config(scan) -> ScanConfig` (defaults +
  overrides from `options`, `active.authorized_by` when active). — RF-10, RF-27
- [x] `webvigil/api/mapping.py`: `store_result(session, scan_id, ScanResult)` and
  `rows_to_result(scan, findings) -> ScanResult`; round-trip test
  (`store_result` → `rows_to_result` == original). — RF-18, RF-19, ADR-6
- [x] `webvigil/api/runner.py`: `ScanRunner` — `start` / `stop` / `wake` / `cancel` /
  `current_scan_id`; the background loop (`claim_next_queued` → `_run_scan` → free the
  slot); `_run_scan` (build config → `Orchestrator.run` → `store_result`; `FAILED` on
  `WebVigilError`; re-raise `CancelledError`); every DB helper self-contained inside
  `to_thread`. — RF-09, RF-10, RF-14
- [x] `webvigil/api/runner.py`: `recover_interrupted_scans(engine)` — `RUNNING` → `INTERRUPTED`
  with a note. — RF-16
- [x] Tests (runner + `Orchestrator` pointed at the spec 001 fixture app via the `transport`
  seam): a `QUEUED` scan runs to `COMPLETED` with findings; a second scan stays `QUEUED`
  while the first runs; `cancel` a `RUNNING` scan → `CANCELLED` and **zero** findings;
  `WebVigilError` → `FAILED`; `recover_interrupted_scans` flips a stray `RUNNING` row. — RF-09, RF-10, RF-14, RF-16
- [x] Quality gate.

## Stage 5 — Scan routes

- [x] `webvigil/api/schemas.py` (part 2): `ScanCreate` (+ `model_validator`: active needs
  `authorized_by`, `Target.parse` rejects bad URLs), `ScanSummary`, `ScanOut`,
  `LocationOut`/`EvidenceOut`/`FindingOut`, `Page[T]`. — RF-08, RF-11, RF-12, RF-13
- [x] `webvigil/api/routes/scans.py` cursor helper: encode/decode base64 `(created_at, id)`;
  `list` orders `created_at DESC, id DESC`. — RF-11, ADR (decision 6)
- [x] `webvigil/api/routes/scans.py`: `POST /api/scans` (`async def`, validate → insert
  `QUEUED` → `runner.wake()` → 201), `GET /api/scans` (filter + cursor page),
  `GET /api/scans/{id}`, `GET /api/scans/{id}/findings` (severity/check_id filter,
  deterministic order). — RF-08, RF-11, RF-12, RF-13
- [x] `webvigil/api/routes/scans.py`: `POST /api/scans/{id}/cancel` (`async def` →
  `runner.cancel`; 409 on terminal, 404 on missing), `DELETE /api/scans/{id}` (204 when
  terminal, 409 otherwise). — RF-14, RF-15
- [x] `webvigil/api/app.py`: complete the lifespan — `run_alembic_upgrade` (when
  `auto_migrate`) → `resolve_session_secret` → `recover_interrupted_scans` → build and
  `start` the `ScanRunner`, put it on `app.state`, `wake()`; `stop` it on shutdown. — RF-16, RF-24
- [x] Tests: create validation (`ftp://` 422, active w/o `authorized_by` 422); full
  lifecycle `QUEUED → RUNNING → COMPLETED`; queue (second stays `QUEUED`); cancel `QUEUED`
  and `RUNNING`; delete terminal (204) vs running (409); list pagination + `status` filter;
  findings filter + order; restart recovery through `create_app`. — RF-08..17
- [x] Quality gate.

## Stage 6 — Reports route

- [x] `webvigil/api/routes/reports.py`: `GET /api/scans/{id}/report?format=&download=` —
  `rows_to_result` → `get_reporter(format).render`; `Content-Type` per format;
  `Content-Disposition` `attachment` (default) or `inline` (`download=false`); 409 for a
  scan with no results; 422 for an unknown format. — RF-18
- [x] Tests: each of the four formats downloads with the right headers; `download=false` →
  `inline`; `json` byte-identical to `get_reporter("json").render(rows_to_result(...))`;
  report on a `QUEUED` scan → 409. — RF-18, RF-19
- [x] Quality gate.

## Stage 7 — `webvigil-web` CLI

- [x] `webvigil/api/cli.py`: Typer app + `main()`; `serve [--host --port --reload]`
  (`uvicorn.run("webvigil.api.app:app", …)` with `WebConfig` defaults, `--reload` off by
  default), `migrate` (`alembic upgrade head`), `reset-password [--username]` (prompt,
  re-hash, update). — RF-29
- [x] Tests (`CliRunner`): `migrate` creates the tables on a tmp DB; `reset-password`
  updates the hash and the old password stops verifying; `serve` calls `uvicorn.run` with
  the resolved host/port (uvicorn mocked). — RF-29
- [x] Quality gate.

## Stage 8 — Ops, docs, packaging

- [x] `docker-compose.yml`: a `webvigil-web serve` service with a named volume for the
  SQLite file and a documented published port. — RF-30
- [x] `docs/web-api.md`: install (`pip install "webvigil[web]"`), first-run setup, config
  reference (`[web]` keys + env), the single backup unit (the `.db` file), and the note
  that the API can start Active-Mode scans. — RF-31, Risks
- [x] `SECURITY.md`: add a line that the Web API can trigger Active Mode (still gated by
  `authorized_by`). — RF-27, Risks
- [x] `README.md`: a "Web API" section (quick start, `webvigil-web serve`, `/docs`).
  `CLAUDE.md`: `webvigil.api` moves from "spec 002" to implemented; command list gains
  `webvigil-web`. `docs/architecture.md`: the persistence layer and API row filled in.
- [x] `specs/README.md`: mark `002-web-api` **done**.
- [x] Run the manual verification checklist: `webvigil-web migrate`, `serve`, complete the
  setup screen via `curl`, create a passive scan against the fixture app, poll to
  `COMPLETED`, download all four report formats, `docker compose up` smoke.
- [x] Final full quality gate; set `requirements.md`, `design.md`, `tasks.md` frontmatter
  `status: done`.
