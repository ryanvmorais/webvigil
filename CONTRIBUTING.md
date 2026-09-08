# Contributing to WebVigil

Thanks for your interest in improving WebVigil.

## Development

WebVigil is managed with [uv](https://docs.astral.sh/uv/). `uv sync` installs the project
plus the `dev` dependency group, which pins the tooling (`ruff`, `black`, `mypy`,
`import-linter`) and the test-only libraries (`pytest*`, `starlette`, `jsonschema`,
`trustme`) — each line in `pyproject.toml` says why it is there.

The full command list, for the engine and the web UI, is in the README's
[Development](README.md#development) section.

## Before opening a pull request

Run the full quality gate and make sure it is green — CI runs the same checks. The
commands are in [README → Development](README.md#development).

## Conventions

- **Language:** all code, comments, docstrings, commit messages, and documentation are in
  English. See [CLAUDE.md](CLAUDE.md).
- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
- **Design changes:** non-trivial features are designed as specs under `specs/` before
  implementation (requirements → design → tasks).

## Writing a new check

Checks live in `src/webvigil/checks/`. Each check subclasses `Check`, declares its metadata
(`id`, `category`, `mode`, `default_severity`, `cwe`, `references`), and implements
`async run(ctx) -> list[Finding]`. Register it with the `@register` decorator.

Every check must ship with unit tests that include both a **vulnerable** fixture (the finding
is reported) and a **hardened** fixture (nothing is reported) to guard against false positives.

See [docs/writing-checks.md](docs/writing-checks.md).

## Reporting security issues

Do not open public issues for vulnerabilities in WebVigil itself — see [SECURITY.md](SECURITY.md).
