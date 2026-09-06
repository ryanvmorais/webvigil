# Web API

`webvigil.api` is an optional FastAPI service that runs scans through the same engine as the
CLI, keeps a history in SQLite, and serves reports. It is **single-user** and **local-first**.
The browser dashboard that consumes it is a separate component (spec 003).

## Install and run

```bash
pip install "webvigil[web]"        # or: uv sync --all-extras
webvigil-web serve                 # http://127.0.0.1:8000  (OpenAPI docs at /docs)
```

Or with Docker:

```bash
docker compose up --build          # http://localhost:8000
```

On first start the database is created and migrated automatically. Open `/docs` (or the
future dashboard) and you will be asked to create the single account.

## Commands

| Command | Purpose |
|---|---|
| `webvigil-web serve [--host --port --reload --config]` | Run the API with uvicorn |
| `webvigil-web migrate [--config]` | Run `alembic upgrade head` explicitly |
| `webvigil-web reset-password [--username --config]` | Set a new password for the user |

## Configuration

The API reads the `[web]` table of `webvigil.toml` (or `--config PATH`, or
`WEBVIGIL_CONFIG`). Every key also has an environment variable:

| `[web]` key | Env var | Default | Meaning |
|---|---|---|---|
| `database_path` | `WEBVIGIL_DATABASE_PATH` | `webvigil.db` | SQLite file |
| `host` / `port` | `WEBVIGIL_WEB_HOST` / `WEBVIGIL_WEB_PORT` | `127.0.0.1` / `8000` | bind address |
| `session_secret` | `WEBVIGIL_SESSION_SECRET` | *generated* | JWT signing key — see below |
| `session_ttl_hours` | `WEBVIGIL_SESSION_TTL_HOURS` | `12` | cookie lifetime |
| `cookie_secure` | `WEBVIGIL_COOKIE_SECURE` | `false` | set `true` behind HTTPS |
| `auto_migrate` | `WEBVIGIL_AUTO_MIGRATE` | `true` | migrate on startup |
| `cors_origins` | `WEBVIGIL_CORS_ORIGINS` | *(none)* | browser origins allowed to send the cookie |

## Authentication

Login sets an httpOnly, `SameSite=Lax` cookie holding a signed JWT. There is no server-side
session store, so "log out everywhere" is not possible without rotating `session_secret`;
the short default TTL bounds exposure. Passwords are argon2id hashes.

**Session secret:** if `session_secret` is unset the server generates one and stores it in
the database (a `setting` row), so sessions survive restarts. Pin `session_secret`
explicitly for a shared or containerised deployment.

## Scan execution

Scans run **one at a time** as an in-process background task; the rest wait in a `queued`
state. Cancelling a running scan stops it and stores no partial findings. If the process
dies mid-scan, that scan is marked `interrupted` on the next start and the queue resumes.

## Active Mode

`POST /api/scans` with `{"mode": "active", "authorized_by": "..."}` starts an Active-Mode
scan — the same gate as the CLI's `--mode active --authorized-by`. The authorization text
is stored on the scan and printed in every report. Only run Active Mode against systems you
are authorized to test (see [SECURITY.md](../SECURITY.md)).

## Backup

The SQLite file (`database_path`) is the only stateful artefact — it holds the user, the
scan history, and the generated session secret. Back it up by copying the file.
