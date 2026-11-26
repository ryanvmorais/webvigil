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
dashboard, see [web-ui.md](web-ui.md)) and you will be asked to create the single account.

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
| `allowed_hosts` | `WEBVIGIL_ALLOWED_HOSTS` | *(none)* | host names the API answers for besides IP addresses, `localhost` and a named `host`; `*` is refused — see below |
| `trusted_proxies` | `WEBVIGIL_TRUSTED_PROXIES` | *(none)* | proxies whose `X-Forwarded-For` is believed: IP addresses, CIDR networks or host names; a network broader than `/8` (IPv4) or `/7` (IPv6) is refused — see below |

## Authentication

Login sets an httpOnly, `SameSite=Lax` cookie holding a signed JWT. There is no server-side
session store, so logging out only clears this browser's cookie, and a stolen token cannot be
revoked without rotating `session_secret`; the short default TTL bounds exposure. Passwords are
argon2id hashes.

**A credential change ends the other sessions.** Changing the password (or running
`webvigil-web reset-password`) rejects every token minted before the change, down to the
fraction of a second; the session that changed it gets a fresh cookie and stays signed in. That
includes a login still being verified when the change lands: its session ends with the others. Of
two changes made at the same time one is stored and the other gets `409`. A session token must
carry its subject, issue time and expiry, or it is refused. `reset-password` enforces the same
policy as the API: 8 to 256 characters.

**Login attempts are throttled, per client.** After 5 failed attempts a client must wait before
trying again, whatever the password: 1 second, doubling with each further failure up to 5 minutes,
answered with `429` and `Retry-After`; a successful login forgets that client's failures. The wait
belongs to the client, so a single client guessing from another address delays only itself. The
state is in memory, per process.

Guesses spread over many addresses are contained by a shared limit per username: 20 attempts in
30 seconds, after which that username waits for the rest of the window. That wait falls on everyone
using the username, so guesses from many addresses can still delay your login for as long as they
last. It is set so one client is always stopped by its own wait first, and a successful login does
not count against it. At most 4 password checks of a login or of the initial setup run at once,
because each one costs a full Argon2 in memory and CPU; the excess gets `429` with
`Retry-After: 1`, and a client already waiting is answered before it competes for one. The password change re-checks the current password
under its own limit, per user, so a stolen session cannot guess it without limit. A username that
does not exist takes the same time as a wrong password (one Argon2 check each) and gets the same
answers, so the response does not say which usernames are real.

**Who the client is.** By default, the address of the connection, and every forwarding header is
ignored. List a reverse proxy in `trusted_proxies` and, for a connection from it, the client is
read from `X-Forwarded-For`, from the right, up to the first address that is not a trusted proxy:
the hops further left were written by the client. `X-Forwarded-Host` never identifies a client. An
IPv6 client is counted by its `/64`. An entry may be a host name, resolved when needed and again
every 30 seconds, which is how the Compose file trusts its `web` service and nothing else on that
network. Without an entry for your proxy all its clients share one wait, so **add it** if you run
one in front of the API, and list only proxies that replace or append to the header: Next's own
proxy forwards what the client sent, so the dashboard's Docker image appends the connection's
address itself, and a dashboard started another way must not be listed. `webvigil-web serve` turns
off uvicorn's handling of these headers, so `trusted_proxies` is the only switch.

**Only known host names are answered.** A request whose `Host`, or whose `X-Forwarded-Host` (the
browser's `Host`, as the dashboard's proxy forwards it), names a host the server does not know gets
`400`. Known are IP addresses, `localhost`, the bind `host` when it is a name, and the names in
`allowed_hosts`. A browser treats a host *name* as the site, whatever address it resolves to, so a
name someone else controls, made to resolve to your loopback address, would otherwise let their
page talk to the API as its own origin; an IP address can only be a page's origin if that address
served it. Behind a reverse proxy with a public name, or when the dashboard reaches the API by a
service name (`api` in the Compose file), list that name in `allowed_hosts`.

**Another origin cannot change state.** A `POST`, `PUT`, `PATCH` or `DELETE` that carries an
`Origin` header is refused with `403` unless the origin is this server's own or one listed in
`cors_origins`. `SameSite=Lax` already keeps a request from another *site* from carrying the
cookie, but a page on another port of the same host is the same site, and a `POST` with no body
(`/api/auth/logout`, `/api/scans/{id}/cancel`) needs no preflight. "Own" is the `Host` the request
arrived with or, behind the dashboard's proxy, its `X-Forwarded-Host`: Next sends the API's own
`Host`, so the browser's `Origin` (the dashboard) only matches the forwarded one. Both headers
have already passed the host check above, so neither can name a host the server does not know. The scheme is not compared (behind a TLS-terminating proxy the API
sees `http` while the browser says `https`), the host and the port are. A request with no `Origin`
(curl, the CLI, another server) is not a browser form or fetch and is not checked. If you put your
own reverse proxy in front of the API and it replaces `Host` without adding `X-Forwarded-Host`,
list the dashboard's origin in `cors_origins`.

**Request sizes are bounded.** A request body over 1 MiB is refused with `413` before the API reads
the rest of it (a scan request is a few kilobytes), the login username and password are capped at
64 and 256 characters like the ones `POST /api/setup` takes, and the table of failed logins keeps at
most 10,000 keys. When it is full it drops the key that failed longest ago among those not waiting;
a key that is waiting is kept, and if every key is waiting, a client not yet in the table waits too,
until the first of those waits ends. A reverse proxy that limits body size as well is still better.

**A `422` repeats nothing it was sent.** A request that fails validation, on any endpoint, gets
`{"detail": [{"type": ..., "loc": [...], "msg": ...}]}`: the error type, where it is and why, never
the value. FastAPI's own `input`, `ctx` and `url` keys are not sent (the OpenAPI schema still lists
them as optional), so a too-long password or a refused target does not go back to the client, or to
a proxy or log in between. A message can still name part of a refused value (the address of a
target with no valid host, an unknown report format), so every string of `loc` and every message is
cut at 1 Ki characters, with control, bidirectional and zero-width characters shown as escapes
(`\x1b`, `\u202e`). In the process, the signing secret and every password are held as
secrets that a log line, a traceback or an error shows as `[redacted]`; only signing and checking a
session token, and hashing and verifying a password, read them.

**Reports are served contained.** A report is built from what the scanned site sent, and
`GET /api/scans/{id}/report?format=html&download=false` shows the HTML one inline, from the API's
own origin. The template escapes everything, so nothing is known to be wrong; these headers are what
would contain a mistake. Every report response carries `X-Content-Type-Options: nosniff`, and the
HTML one also `Content-Security-Policy: sandbox; default-src 'none'; style-src 'unsafe-inline'`: the
page gets a unique origin with no script, form or fetch, and keeps its inline `<style>`, which is
all the self-contained report uses. The dashboard's preview does not depend on it (it renders a
`blob:` in a sandboxed iframe).

**The `/docs` page loads a pinned Swagger UI.** The page runs on the API's own origin, so it names
an exact `swagger-ui-dist` release on jsDelivr and the SHA-384 of each file (Subresource
Integrity): the browser refuses a file that does not match, and the request carries no cookie. The
page needs internet access to load; the API itself does not. `scripts/update-swagger-ui.py` moves
the pin to a newer release. ReDoc (`/redoc`) is not served.

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
is refused: the API sends the session cookie), add the public host name to `allowed_hosts` and list
the proxy in `trusted_proxies`. `webvigil-web serve` prints a warning when it
listens beyond this machine with `cookie_secure` off; `docker compose` binds every interface
inside the container and publishes the port on `127.0.0.1` only, so the warning shows there and is
expected. Login attempts are throttled (see Authentication), but that state is per process and
in memory: a proxy that limits them too is better.

## Scan execution

Scans run **one at a time** as an in-process background task; the rest wait in a `queued`
state, at most 100 of them (a new scan beyond that gets `429`). Cancelling a running scan stops it
and stores no partial findings; once its result is in and being written, a cancel gets `409` and
the scan ends `completed`. If the process dies mid-scan, that scan is marked `interrupted` on the
next start and the queue resumes. A scan that crashes is `failed` with the error `internal error`;
the server log says where, not the API.

**What the server log shows.** A crash can carry what the scanned site sent, so the API's own
loggers, uvicorn's `uvicorn.error` and the HTTP client's `httpx2` pass every record through one
filter. The message is cut at 16 Ki characters and kept on one line, with control, bidirectional
and zero-width characters shown as escapes. A traceback is rebuilt the same way: the frames as
Python writes them, each exception's message on a line of its own, up to 64 Ki characters in all.
The filter changes neither the level nor the handlers, so the logging uvicorn or the operator set
up still applies. A scan whose engine raised an error nothing expects is logged as
`scan <id> failed (<type>)` with the frames and the exception types, the paths cut to the install
and no message, as a check's error appears in a report: that message may quote anything the scan
held. A database error names the failed statement but never its values, so finding text and
password hashes stay out of the log.

## Active Mode

`POST /api/scans` with `{"mode": "active", "authorized_by": "..."}` starts an Active-Mode
scan — the same gate as the CLI's `--mode active --authorized-by`. The authorization text
is stored on the scan and printed in every report. Only run Active Mode against systems you
are authorized to test (see [SECURITY.md](../SECURITY.md)).

## What a scan request cannot carry

A scan request takes a target, a mode, a scope and a few limits. It does **not** take a path or a
URL to read: neither `--openapi` nor `--har` (a browser recording, [`har-import.md`](har-import.md))
is exposed, because a path in a request would be read from the server's disk by whoever sent it. A
field a request holds that the API does not define is ignored. Scan with those options from the CLI.

Every option has a ceiling, and a request over one gets `422`: `max_pages` up to 10 000, `delay_ms`
up to 60 000, a `target` of up to 2 048 characters, an `authorized_by` of up to 256, and up to 200
`disabled_checks` of up to 128 characters each. A `target` with a credential in it
(`https://user:password@host/`) gets `422` as well, and nothing is stored: send HTTP Basic
credentials as a header from the CLI ([`authenticated-scanning.md`](authenticated-scanning.md)). A
stored target is the normalized URL, which never kept a credential.

## Backup

The SQLite file (`database_path`) is the only stateful artefact — it holds the user, the
scan history, and the generated session secret. Back it up by copying the file. It is created
readable by its owner only (`0600`, in a `0700` directory when the server creates it), and an
existing one, with its `-wal` and `-shm` files, is set to `0600` on start; keep the same mode on
the copy.
