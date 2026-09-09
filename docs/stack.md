# The stack, and why

Every load-bearing technology in WebVigil, what it does, why it was chosen over
the alternative, and the handful of concepts worth learning first if it is new
to you.

This is not exhaustive — the full version graph is pinned in `uv.lock` and
`web/pnpm-lock.yaml`, and per-feature decisions live in the `### ADR-N` blocks of
`specs/*/design.md`. This page is the map: the *shape* of the project and the
reasoning behind each piece.

The project is three programs sharing one engine:

```
CLI (Python)  ─┐
Web API (Python, FastAPI)  ─┼─►  webvigil.core  (the scan engine, a pure library)
Web UI (web/, Next.js)  ────┘        talks only to the Web API, never the engine
```

---

## Language and packaging

### Python 3.12+

The engine, CLI and Web API. 3.12 is the floor for `type` statement syntax
(PEP 695), better error messages, and the performance work in 3.11/3.12.

**Why not** a compiled language: the value is in the check logic and the
HTTP/parsing handling, not raw speed; a scanner spends its time waiting on the
network. Python's ecosystem for HTTP, parsing and CLIs is unmatched.

**Learn:** `async`/`await` and `asyncio` (the engine is async end to end),
type hints (`X | None`, `list[str]`, `Protocol`), dataclass-style modelling.

### uv

The Python package manager and virtual-env tool (from Astral, the Ruff people).
Replaces `pip` + `pip-tools` + `virtualenv` + `pipx`. `uv sync` installs the
locked graph; `uv run` executes inside the env; `uv lock` resolves.

**Why not** Poetry / PDM / plain pip: uv is an order of magnitude faster, uses
the standard `pyproject.toml` (PEP 621) with a real lockfile (`uv.lock`), and
needs no plugins.

**Learn:** `uv sync` / `uv sync --all-extras`, `uv run <cmd>`, `uv add` /
`uv lock`, the split between `[project.dependencies]` (runtime),
`[project.optional-dependencies]` (the `web` extra) and `[dependency-groups]`
(dev tooling).

### Node 24 + pnpm — Web UI only

Node is the JavaScript runtime the Next.js dev server and build run on; pnpm is
its package manager. Node 24 is the current Active LTS (Node 20 reached
end-of-life in April 2026). pnpm is pinned by the `packageManager` field in
`web/package.json`.

**Why not** npm / yarn: pnpm is faster, uses a content-addressed store (one copy
of a package on disk, hard-linked into each project), and its lockfile
(`pnpm-lock.yaml`) resolves more strictly.

**Learn:** `pnpm install`, `pnpm <script>` (runs a `package.json` script),
`pnpm dlx` (run a package without installing), the `dependencies` vs
`devDependencies` split, and `pnpm.overrides` (force a transitive version — used
here to patch `js-yaml`).

### TypeScript

The Web UI is TypeScript in `strict` mode — every value has a checked type.
`pnpm typecheck` runs `tsc --noEmit` (type-check only, no output; Next and Vitest
do the actual compiling).

**Why not** plain JavaScript: the UI is a typed client of a typed API (see
*openapi-typescript* below); losing types there would defeat the point.

**Learn:** `interface` vs `type`, generics, `unknown` vs `any`, discriminated
unions, `as const`, and how types flow from a schema (`components["schemas"]["ScanOut"]`).

---

## The engine and CLI (Python)

### httpx

The async HTTP client the whole engine runs on. `webvigil.http` wraps one
`httpx.AsyncClient` with retry, redirect control (`follow_redirects=False` — the
scanner walks the redirect chain itself, scope-checking every hop), timeouts and
per-request statistics.

**Why not** `requests`: `requests` is sync-only. **Why not** `aiohttp`: httpx
has a cleaner API, HTTP/2 support, and a sync mode for tests.

**Learn:** `AsyncClient`, `Response` (`.text`, `.content`, `.headers`,
`.history`), `httpx.Headers` (case-insensitive, multi-value for `Set-Cookie`),
the transport/timeout/retry model, and `MockTransport` for tests.

### selectolax

A very fast HTML parser (a binding over the C library Lexbor). Used to pull
links, forms, `<script src>`, meta tags and inline content out of fetched pages.

**Why not** BeautifulSoup / lxml: selectolax is 5–30× faster and the parse step
runs on every crawled page. The API is small — CSS selectors and node text.

**Learn:** `HTMLParser(html)`, `.css(selector)` / `.css_first(selector)`,
`node.attributes`, `node.text()`.

### pydantic v2

The single modelling mechanism: config, `Finding`, `Severity`, `ScanResult`,
and every Web API request/response body. Models are frozen (`frozen=True`) and
reject unknown keys (`extra="forbid"`), so a typo in a TOML config or an API
payload raises instead of being silently ignored.

**Why not** dataclasses / attrs: pydantic does validation, parsing (TOML/JSON →
typed object), and lossless serialization (`.model_dump()` with field aliases)
in one place. v2's core is written in Rust and is fast.

**Learn:** `BaseModel`, `Field(...)`, `model_config` (`ConfigDict`),
`model_validate` / `model_dump` / `model_dump_json`, validators
(`@field_validator`), and how FastAPI uses these models for automatic request
validation and OpenAPI generation.

### Typer + Rich

Typer builds the CLI (`webvigil scan`, `list-checks`, `report`) from type-hinted
functions — a function signature becomes the argument parser and the `--help`
text. Rich renders the coloured terminal output (tables, the severity summary).

**Why not** `argparse` / `click` directly: Typer *is* Click underneath, with the
boilerplate replaced by type hints. Rich is the standard for terminal formatting.

**Learn:** a Typer command is just a function with `typer.Option` / `typer.Argument`
defaults; `typer.Exit(code=...)`; Rich `Console`, `Table`, and `Console(stderr=True)`
(the summary goes to stderr so `--format` output can be piped from stdout).

### Jinja2

The template engine for the HTML report. `webvigil.reporting` renders a single
self-contained HTML file — no external CSS, JS or fonts — from `report.html.j2`.

**Why not** string building or a heavier site generator: the report is one
templated file; Jinja2 is the obvious tool and is already a FastAPI/Flask
staple.

**Learn:** `Environment`, `{{ }}` / `{% %}` / `{# #}`, autoescaping,
`trim_blocks`/`lstrip_blocks`, and template inheritance (not used here — the
report is one flat template).

### cryptography

Used by the TLS checks to inspect a server's certificate: parse it, read the
chain, expiry, key size, signature algorithm.

**Why not** the stdlib `ssl` module alone: `ssl` gives you the handshake but
poor certificate introspection; `cryptography` parses X.509 properly.

**Learn:** `x509.load_der_x509_certificate`, `cert.not_valid_after_utc`,
`cert.public_key()`, `cert.signature_hash_algorithm` — only the read side.

### packaging

The reference implementation of Python's version specifiers. The dependency
fingerprint check uses it to decide whether a detected library version falls in
a "vulnerable `>= 1.2, < 1.4.1`" range from the Retire.js / OSV data.

**Learn:** `Version("1.4.0")`, `SpecifierSet(">=1.2,<1.4.1")`, and
`version in specifier_set`.

---

## The Web API (Python, `[web]` extra)

### FastAPI

The web framework for the API service (`webvigil-web serve`). Routes are
type-hinted functions; FastAPI validates the request against the pydantic model,
calls the handler, serializes the response, and — the reason it was chosen —
**generates the OpenAPI schema automatically**. That schema is what the Web UI's
types are generated from.

**Why not** Django: Django is a batteries-included framework built around its own
ORM, admin, templates and forms. WebVigil's API is a thin async wrapper over a
Python library with a single-user auth model — Django would be weight to fight,
not leverage. **Why not** Flask: Flask is sync-first and has no built-in schema
generation or request validation.

**Learn:** path-operation functions (`@app.get`, `@router.post`), dependency
injection (`Depends`), `APIRouter`, the `lifespan` context (startup/shutdown —
here it runs Alembic and starts the scan runner), `Response`/`status_code`, and
how a pydantic model in the signature becomes both validation and schema.

### Uvicorn

The ASGI server that actually runs the FastAPI app (FastAPI is a framework, not a
server). `webvigil-web serve` launches it. `[standard]` pulls in the fast
`uvloop`/`httptools` implementations.

**Learn:** just that ASGI is the async successor to WSGI, and that
`uvicorn.run(app, host=, port=)` is the entry point.

### SQLModel

The ORM for the API's SQLite database (scan history, the single user). SQLModel
is pydantic models + SQLAlchemy tables in one class — so a row and an API body
can share a base. Spec 002 keeps **three** model layers on purpose (ADR-6):
engine models, DB models, wire models — SQLModel is the DB layer.

**Why not** the Django ORM (not using Django) or raw SQLAlchemy: SQLModel is by
the FastAPI author and lines up with the pydantic-everywhere choice.

**Learn:** `SQLModel` with `table=True`, `Field(primary_key=True, ...)`,
`Session`, `select()`, `session.exec()`, `session.add`/`commit`/`refresh`. Note
the engine keeps sessions **sync**, with async confined to the scan runner
(ADR-1).

### Alembic

Database migrations. Every schema change is a versioned migration script; the
API runs `alembic upgrade head` on startup. `create_all()` is deliberately never
used (ADR-8) so that the schema history is always real and reversible.

**Learn:** `alembic revision --autogenerate -m "..."`, `alembic upgrade head` /
`downgrade`, the `versions/` directory, and that `env.py` is wired to read the
DB URL from the app config.

### argon2-cffi

Hashes the single user's password. Argon2 is the current password-hashing
standard (winner of the Password Hashing Competition) — memory-hard, tunable.

**Why not** bcrypt / PBKDF2: still fine, but Argon2id is the modern default and
`argon2-cffi` has a clean API.

**Learn:** `PasswordHasher().hash(password)` and `.verify(hash, password)` —
that's the whole surface.

### PyJWT

Signs and verifies the session cookie. The API uses a **stateless** JWT cookie
(ADR-4): no server-side session table — the signed token *is* the session. The
signing secret is generated and persisted on first run if unset (ADR-5).

**Why not** a server-side session store (Redis, a DB table): for a single-user
local tool it is pure overhead. The trade-off — you cannot revoke one token
early — does not matter here.

**Learn:** `jwt.encode(payload, secret, algorithm="HS256")`,
`jwt.decode(token, secret, algorithms=[...])`, `exp` / `iat` claims, and
`InvalidTokenError`.

---

## The Web UI (`web/`)

### Next.js 16 (App Router)

The React framework the dashboard is built with. Here it is used as a **thin
client**: `output: "standalone"` for the Docker image, a `next.config` rewrite
that proxies `/api/*` to the FastAPI service server-side (so the browser sees one
origin, the `SameSite=Lax` cookie works, and there is no CORS — ADR-3), and
almost nothing else Next offers. Every page is a client component.

**Why not** server-rendered templates (FastAPI + Jinja2, or Django): the
dashboard is genuinely interactive — it polls running scans, filters a findings
table, shows live status. **Why not** plain React + Vite: Next gives the
standalone build, the dev server, and the routing for free, and is the
mainstream default. The cost — Next.js has shipped a high volume of security
advisories — is bounded here because the app is single-user, local, and never
internet-facing.

**Learn:** the App Router (`app/` directory, `page.tsx` / `layout.tsx`),
`"use client"` (this app is all client components), `next/navigation` hooks
(`useRouter`, `useParams`, `useSearchParams`), `next.config.ts` `rewrites()`,
and `output: "standalone"`. You can skip Server Components, Server Actions and
caching — they are not used.

### React 19

The UI library. Components are functions that return JSX; state is `useState` /
`useReducer`; side effects are `useEffect`; shared logic is custom hooks.

**Learn:** function components, the hook rules, `useState` / `useEffect` /
`useRef` / `useMemo` / `useCallback`, lifting state up, and why the new
`eslint-plugin-react-hooks` (v6, React Compiler rules) complains about reading a
ref during render.

### TanStack Query

The **only** store for server state (ADR-5). Every API call goes through a
`useQuery` / `useMutation` hook: it caches, dedupes, refetches, and tracks
loading/error. Liveness (scan list, scan detail) is polling — `refetchInterval`
gated on non-terminal status and tab visibility; there is no WebSocket/SSE.

**Why not** Redux / Zustand / raw `useEffect` + `fetch`: those are for *client*
state; server state has different needs (caching, staleness, background refetch)
that Query handles and hand-rolled code gets wrong.

**Learn:** `QueryClient` / `QueryClientProvider`, `useQuery({ queryKey, queryFn })`,
`useMutation`, `useInfiniteQuery` (the scan list — ADR-6), query keys and
`queryClient.invalidateQueries`, `staleTime` vs `gcTime`, and `refetchInterval`.

### The typed API contract — openapi-typescript

The link that makes "typed client of a typed API" real. `scripts/dump-openapi.py`
writes `web/openapi.json` from the FastAPI app; `pnpm gen:api` runs
`openapi-typescript` to turn that into `web/src/lib/api-types.ts`. Both files are
committed and a CI step fails if they drift (ADR-4). All calls go through one
wrapper, `web/src/lib/api.ts`, that is typed against them.

**Learn:** the flow (`dump-openapi.py` → `openapi.json` → `gen:api` →
`api-types.ts`), and how to read a generated type
(`components["schemas"]["ScanOut"]`, `paths["/api/scans"]["get"]`).

### Tailwind CSS v4

Utility-first CSS: you style in the markup with classes (`flex`, `gap-4`,
`text-severity-high`) instead of writing CSS files. v4 is configured CSS-first —
`@import "tailwindcss"` and an `@theme` block in `globals.css`, no
`tailwind.config.ts`. The design tokens (the shadcn "slate" palette, a severity
scale) are CSS custom properties; dark mode is `prefers-color-scheme` only, no
toggle (ADR-8).

**Why not** CSS Modules / styled-components / plain CSS: utilities keep styling
co-located with the component and produce a tiny final stylesheet (only the
classes you used). shadcn/ui assumes Tailwind.

**Learn:** the common utilities (layout: `flex`/`grid`/`gap`/`p`/`m`; type;
colour), responsive prefixes (`sm:` `md:`), state prefixes (`hover:`
`data-[state=open]:`), `@theme` and CSS-variable tokens, and the `cn()` helper
(`clsx` + `tailwind-merge`) for conditional/merged classes.

### shadcn/ui + Radix UI

shadcn/ui is **not a dependency** — it is a CLI that copies component source
(Button, Dialog, Select, …) into `web/src/components/ui/`, so you own and can
edit them. Those components are built on **Radix UI** primitives
(`@radix-ui/react-*`), which provide the accessible, unstyled behaviour
(focus management, keyboard nav, ARIA) while Tailwind provides the look.

**Why not** MUI / Chakra / Ant Design: those are heavy, opinionated, and hard to
restyle. shadcn gives you a starting point you then own outright.

**Learn:** that `components/ui/*` is vendored (regenerate with
`pnpm dlx shadcn@latest add <name>`), the Radix compound-component pattern
(`<Dialog><DialogTrigger/><DialogContent/></Dialog>`), `asChild`, and the
`data-[state]` attributes Radix exposes for styling.

### react-hook-form + Zod

For the two non-trivial forms — new-scan and change-password (ADR-11). Zod
defines the schema (types + validation rules) once; react-hook-form manages the
field state, validation timing and error display, with `@hookform/resolvers`
bridging the two.

**Why not** controlled `useState` per field: RHF is uncontrolled (fewer
re-renders) and handles the tedious parts. Zod schemas also produce TypeScript
types for free (`z.infer`).

**Learn:** `z.object({...})` / `.refine` / `z.infer`, `useForm({ resolver:
zodResolver(schema) })`, `form.register` / `form.control` / `form.handleSubmit`,
`<FormField>` (the shadcn wrapper), and `form.setError` (used to show
server-side field errors).

---

## Tooling

### Ruff, Black, Mypy

The Python quality gate, run in order. **Ruff** lints (it replaces Flake8 +
isort + pyupgrade + more) and is near-instant. **Black** formats
(non-negotiable style, no bikeshedding). **Mypy** in `strict` mode checks types
(`src` only — the tests are exercised by pytest).

**Learn:** you mostly just run them (`uv run ruff check .`, `uv run black .`,
`uv run mypy src`) and read the errors; the config is in `pyproject.toml`
`[tool.*]`.

### import-linter

Enforces the architecture contract in CI (ADR-1): the engine packages
(`core`, `http`, `crawler`, `checks`, `reporting`) may **not** import Typer,
Rich, FastAPI, SQLModel, Alembic, PyJWT or argon2, and `webvigil.cli` /
`webvigil.api` may not import each other. `uv run lint-imports` checks it.

**Learn:** the contract lives in `pyproject.toml` `[tool.importlinter]`; a
violation means you leaked a UI/DB dependency into the pure engine.

### pytest (+ pytest-asyncio, pytest-httpx, trustme, jsonschema, Starlette)

The test runner. `asyncio_mode=auto` means `async def test_*` just works.
`pytest-httpx` mocks HTTP at the transport layer. `trustme` mints throwaway TLS
certificates for the TLS-check tests. `jsonschema` validates the SARIF reporter
output against the bundled 2.1.0 schema. **Starlette** runs the insecure/hardened
fixture app that the integration tests scan for real.

**Learn:** fixtures (`@pytest.fixture`, `conftest.py`), parametrization
(`@pytest.mark.parametrize`), `assert` rewriting, `pytest -k <expr>` /
`pytest path::test_name` to run a subset, and the "vulnerable fixture +
hardened fixture" pattern every check test uses.

### Playwright — Web UI end-to-end

Drives a real Chromium browser through one full flow (setup → login → scan →
report → logout), against the real API and engine on a throwaway SQLite file,
fully offline (ADR-9). `playwright.config.ts` starts three processes: the
fixture target app, `webvigil-web serve`, and the built Next app.

**Learn:** `test()` / `expect()`, locators (`page.getByRole`, `getByLabel`,
`getByText`), `page.goto` / `click` / `fill`, auto-waiting, the `webServer`
config option, and `--headed` / `--debug` for watching a run.

### Vitest + Testing Library + MSW + jest-axe — Web UI unit

**Vitest** is the test runner (Jest-compatible API, Vite-fast). **Testing
Library** renders a component and queries it the way a user would (by role, label,
text). **MSW** (Mock Service Worker) intercepts `fetch` so a component test hits
fake API responses. **jest-axe** asserts a rendered tree has no accessibility
violations.

**Learn:** `describe`/`it`/`expect`, `vi.fn()` / `vi.mock` / `vi.hoisted`,
`render()` + `screen.getByRole(...)`, `userEvent.click(...)`, MSW handlers
(`http.get(...)`), and `expect(container).toHaveNoViolations()`.

---

## Smaller pieces

| Package | Role |
|---|---|
| `python-multipart` | lets FastAPI parse `multipart/form-data` (file-upload endpoints) |
| `rich` | (see Typer + Rich) terminal tables and colour |
| `clsx` | join class names conditionally: `clsx("a", cond && "b")` |
| `tailwind-merge` | resolve conflicting Tailwind classes (`p-2 p-4` → `p-4`); paired with clsx in `cn()` |
| `class-variance-authority` (cva) | define a component's class variants (size, intent) as a typed function |
| `lucide-react` | the icon set (`<ShieldCheck />`) |
| `sonner` | toast notifications |
| `tw-animate-css` | the `animate-in` / `fade` / `zoom` / `slide` utilities Radix components use (v4 successor to `tailwindcss-animate`) |
| `prettier` + `prettier-plugin-tailwindcss` | formats the web code; the plugin also sorts Tailwind classes |
| `eslint` + `eslint-config-next` | lints the web code (Next's rules + React hooks + jsx-a11y) |

---

## What is deliberately *not* in the stack

- **Django** — the API is a thin async library wrapper; Django's ORM/admin/forms
  would be weight to fight. FastAPI + SQLModel covers it with less.
- **Redis / Celery / a task queue** — one scan runs at a time, in-process, in a
  single background task (spec 002 ADR-2). A queue is future infrastructure the
  project deliberately avoids.
- **A server-side session store** — the JWT cookie is stateless (ADR-4).
- **Redux / Zustand / a client state manager** — TanStack Query owns server
  state; the little client state there is lives in `useState` and the URL.
- **An axios / ky HTTP wrapper in the UI** — one hand-written typed `fetch`
  wrapper (`api.ts`) is enough and stays honest about the OpenAPI contract.
- **GraphQL** — REST + a generated OpenAPI client is simpler for a
  single-consumer API.
- **A headless browser in the engine** — the crawler parses HTML only; a
  JS-rendered SPA is out of scope (see `docs/notes/why-not-oast.md` and the
  README "Scope and limitations").
- **An OAST / collaborator server** — blind SSRF/XXE detection would need a
  hosted service, which crosses "the engine talks only to the target".
