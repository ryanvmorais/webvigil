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
| `session_secret` | `WEBVIGIL_SESSION_SECRET` | *generated* | JWT signing key, at least 32 characters when pinned — see below |
| `session_ttl_hours` | `WEBVIGIL_SESSION_TTL_HOURS` | `12` | cookie lifetime |
| `cookie_secure` | `WEBVIGIL_COOKIE_SECURE` | `false` | set `true` behind HTTPS |
| `auto_migrate` | `WEBVIGIL_AUTO_MIGRATE` | `true` | migrate on startup |
| `cors_origins` | `WEBVIGIL_CORS_ORIGINS` | *(none)* | browser origins allowed to send the cookie; `*` is refused |

## Authentication

Login sets an httpOnly, `SameSite=Lax` cookie holding a signed JWT. There is no server-side
session store, so logging out only clears this browser's cookie, and a stolen token cannot be
revoked without rotating `session_secret`; the short default TTL bounds exposure. Passwords are
argon2id hashes.

**A credential change ends the other sessions.** Changing the password (or running
`webvigil-web reset-password`) rejects every token minted before the change; the session that
changed it gets a fresh cookie and stays signed in.

**Login attempts are throttled.** After 5 failed attempts a client address, or a username, must
wait before trying again, whatever the password: 1 second, doubling with each further failure up
to 5 minutes, answered with `429` and `Retry-After`; a successful login forgets the failures. The
state is in memory, per process. Behind a reverse proxy every request carries the proxy's address
(`X-Forwarded-For` is not trusted: the client controls it), so the per-username limit is what
holds. Someone guessing can delay you by a few minutes, never lock you out. A username that does
not exist takes the same time as a wrong password (one Argon2 check each) and gets the same
answer, so the response does not say which usernames are real.

**Another origin cannot change state.** A `POST`, `PUT`, `PATCH` or `DELETE` that carries an
`Origin` header is refused with `403` unless the origin is this server's own or one listed in
`cors_origins`. `SameSite=Lax` already keeps a request from another *site* from carrying the
cookie, but a page on another port of the same host is the same site, and a `POST` with no body
(`/api/auth/logout`, `/api/scans/{id}/cancel`) needs no preflight. "Own" is the `Host` the request
arrived with or, behind the dashboard's proxy, its `X-Forwarded-Host`: Next sends the API's own
`Host`, so the browser's `Origin` (the dashboard) only matches the forwarded one. A page of another
site can set neither header. The scheme is not compared (behind a TLS-terminating proxy the API
sees `http` while the browser says `https`), the host and the port are. A request with no `Origin`
(curl, the CLI, another server) is not a browser form or fetch and is not checked. If you put your
own reverse proxy in front of the API and it replaces `Host` without adding `X-Forwarded-Host`,
list the dashboard's origin in `cors_origins`.

**Request sizes are bounded.** A request body over 1 MiB is refused with `413` before the API reads
the rest of it (a scan request is a few kilobytes), the login username and password are capped at
64 and 256 characters like the ones `POST /api/setup` takes, and the table of failed logins keeps at
most 10,000 keys, dropping the one that failed longest ago. A reverse proxy that limits body size
as well is still better.

**Session secret:** if `session_secret` is unset the server generates one and stores it in
the database (a `setting` row), so sessions survive restarts. Pin `session_secret`
explicitly for a shared or containerised deployment. A pinned secret must be at least 32
characters: a shorter one is refused at start with a one-line error (exit code `4`) that shows how
to generate one (`python -c 'import secrets; print(secrets.token_urlsafe(48))'`). Changing the
secret signs every session out.

## Who can reach it

The API is **local-first and single-user**: `webvigil-web serve` binds to `127.0.0.1`, and
`docker compose` publishes the API, the dashboard and the optional test target on `127.0.0.1`
only. Two things make that the right default:

- **First-run setup is open.** Until the first account exists, `POST /api/setup` is
  unauthenticated (it answers `409` afterwards). Whoever reaches a fresh instance first creates
  the account, so create yours right after starting it, and never leave a new instance
  reachable from a network.
- **A signed-in user can make the host scan any URL it can reach**, internal addresses
  included, and run Active Mode from the host's address. That is what a scanner is for, and it is
  why the account is the only access control.

If you expose it on purpose (another machine, a reverse proxy), do it over HTTPS with
`cookie_secure = true`, pin a long random `session_secret`, list `cors_origins` explicitly (a `*`
is refused: the API sends the session cookie). `webvigil-web serve` prints a warning when it
listens beyond this machine with `cookie_secure` off; `docker compose` binds every interface
inside the container and publishes the port on `127.0.0.1` only, so the warning shows there and is
expected. Login attempts are throttled (see Authentication), but that state is per process and
in memory: a proxy that limits them too is better.

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
