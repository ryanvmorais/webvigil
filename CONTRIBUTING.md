# Contributing to WebVigil

Thanks for your interest in improving WebVigil.

## Development setup

```bash
uv sync
uv run pytest
```

## Before opening a pull request

Run the full quality gate — CI runs the same checks:

```bash
uv run ruff check .
uv run black --check .
uv run mypy src
uv run pytest
```

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
