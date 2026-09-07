# Keeping a security engine honest with import-linter

> Design note for [WebVigil](https://github.com/ryanvmorais/webvigil). Background for
> [spec 001 — foundation](../../specs/001-foundation/design.md) and the architecture
> summary in [CLAUDE.md](../../CLAUDE.md).

WebVigil is four things in one repository: a scan **engine**, a **CLI**, an optional **web
API**, and a **Next.js dashboard**. The engine — `webvigil.core`, `webvigil.http`,
`webvigil.crawler`, `webvigil.checks`, `webvigil.reporting` — is meant to be a pure library.
It is what you would `import` to build your own tool on top of WebVigil's scanning.

For that to be true and stay true, the engine has to keep its distance from everything
else. The rule is:

- the engine never imports Typer, Rich, FastAPI, SQLModel, Alembic, `pyjwt`, or `argon2`;
- the CLI and the web API never import each other;
- the dashboard only ever talks to the API over HTTP.

Those are not comments in a style guide. They are enforced by `import-linter` contracts that
run in CI, and a violation fails the build.

## Why a security tool in particular needs this

### Auditability

A security engine you cannot reason about is a liability. If `webvigil.checks.injection`
could reach into a FastAPI request object or a SQLModel session, then reviewing what the
SQL-injection detector actually does means reviewing a slice of a web framework and an ORM
along with it. Keeping the engine's dependency surface small — `httpx`, `pydantic`,
`selectolax`, the standard library — keeps the trust boundary small. You can read the engine
and know what it can and cannot do.

### Reusability

The entire point of "engine plus thin clients" is that someone can embed the scan engine in
their own CI tool, their platform, a notebook — without dragging in a web framework, a
database migration system, and a JWT library they will never call. If the engine quietly
depended on FastAPI, "just use the engine" would mean "install the whole stack."

### Blast radius

A CVE in FastAPI should not be able to touch the CLI. A bug in the CLI's argument parsing
should not be reachable from the API. Boundaries that are actually enforced mean a problem
in one client stays in that client.

## Making the rule real

The enforcement is about fifteen lines of configuration. Two contracts:

1. **"Engine stays independent of UI and persistence."** A forbidden-modules contract:
   the engine packages are declared, the forbidden imports are listed, and any path from one
   to the other is a failure.
2. **"CLI and web API do not import each other."** An independence contract between the two
   interface packages.

Every pull request runs `lint-imports` as part of the quality gate, alongside `ruff`,
`black`, `mypy`, and the test suite. The contract turns an architectural *intention* — "the
engine should be standalone" — into a mechanically checked *invariant*. Nobody has to
remember it in code review, and it survives the refactor six months from now that would
otherwise have quietly coupled two layers "just this once."

## The discipline shows up in decisions the contract doesn't cover

When `v0.10` added the OSV.dev advisory lookup, the provider needed an HTTP client. The
obvious move was to reuse the scan's `HttpClient`. But that client is deliberately
target-scoped: it attaches the authenticated-scan cookies, it runs through the shared rate
limiter, and it enforces the scope guard — all of which assume "the target." Routing an
`api.osv.dev` request through it would have meant punching a hole in the scope guard, which
is the exact coupling the guard exists to prevent.

The contract did not forbid that specifically. But the habit the contract builds — keep the
boundaries clean, don't reach across a layer for convenience — pointed at the right answer:
a separate `httpx.AsyncClient`, restricted to the OSV host, that the target-scoped client
knows nothing about. "The engine talks only to the target" stays literally true, and the
one deliberate exception is visibly separate.

## The broader point

Architecture that isn't enforced is a suggestion, and suggestions lose to deadlines. A
contract test is cheap to write and cheap to run, and it is the difference between a
boundary that exists in a diagram and a boundary that is still there after a year of
changes. For a tool whose job is to be trusted, that difference is the whole thing.
