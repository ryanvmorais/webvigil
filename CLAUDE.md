# WebVigil — instruções do projeto

## O que é

Scanner de vulnerabilidades em aplicações web, open source, para desenvolvedores.
Engine Python reutilizável + CLI + Web UI opcional. Modelo mental: OWASP ZAP / Nuclei / Trivy.

## Convenção de idioma

**Código em inglês.** Projeto open source com README em inglês e público internacional
(regra do CLAUDE.md global: "Open source com README em inglês / público estrangeiro → Inglês").

Aplica-se a: nomes de classes/funções/variáveis/constantes, commits, branches, docstrings,
comentários técnicos, specs e documentação (`docs/`, `specs/`).

Exceções: keywords da linguagem; termos técnicos universais (HTTP, URL, TLS, CWE, CVE, CSP,
CORS, SARIF, JSON...); nomes impostos por frameworks; strings visíveis ao usuário final da
Web UI (podem ter i18n depois — o produto ainda não define público-alvo de idioma).

Conversa com o Ryan e o arquivo de plano seguem em português.

## Stack

- **Engine/CLI:** Python 3.12+, `uv`, `httpx`, `pydantic` v2, `typer`+`rich`, `jinja2`,
  `cryptography`, `selectolax`.
- **Web API (extra `web`):** `fastapi`, `uvicorn`, `sqlmodel`+`alembic` (SQLite), `argon2-cffi`, `pyjwt`.
- **Web UI:** `web/` — Next.js (App Router) + TypeScript + Tailwind + shadcn/ui + TanStack Query, gerido por `pnpm`.
- **Qualidade:** `ruff` → `black` → `mypy` (strict) → `import-linter` → `pytest` (`asyncio_mode=auto`).

## Comandos

```bash
uv sync --all-extras
uv run ruff check .
uv run black --check .
uv run mypy src
uv run lint-imports      # contrato: engine não importa Typer/Rich/FastAPI/SQLModel/Alembic/pyjwt/argon2
uv run pytest
uv run webvigil scan <url>
uv run webvigil list-checks
uv run webvigil report <scan.json> --format html
uv run webvigil-web serve            # Web API (extra `web`) — /docs em http://127.0.0.1:8000
uv run webvigil-web migrate
uv run python scripts/dump-openapi.py  # regenera web/openapi.json após mudar a API
uv run python scripts/update-retirejs-db.py  # atualiza a base Retire.js vendorada (spec 004)
```

Web UI (`web/`, gerido por `pnpm`):

```bash
cd web
pnpm install
pnpm dev                             # http://localhost:3000 (proxy /api/* → :8000)
pnpm lint && pnpm format:check && pnpm typecheck && pnpm test && pnpm build
pnpm gen:api                          # api-types.ts a partir de openapi.json
pnpm test:e2e                         # Playwright: setup → scan → report → logout, offline
```

## Arquitetura (resumo)

Camadas, de cima para baixo:

1. **Interfaces** — CLI (`webvigil.cli`) e Web API (`webvigil.api`, extra `web`, entry point
   `webvigil-web`). Clientes finos do `Orchestrator`.
2. **Scan Engine** (`webvigil.core`) — biblioteca pura, sem dependência de UI nem de banco:
   `Orchestrator`, `Target`/escopo/política, HTTP layer (`webvigil.http`), crawler leve
   (`webvigil.crawler`), registry de checks, modelo de `Finding`/`Severity`.
3. **Checks** (`webvigil.checks`) — plugins `PASSIVE`/`ACTIVE`, registrados por decorator +
   entry points. Contrato: `Check.run(ctx: ScanContext) -> list[Finding]`. `webvigil.checks.deps`
   (spec 004) faz fingerprint passivo de libs JS do front + match com uma base Retire.js
   vendorada (offline); o passo de fingerprint roda no `Orchestrator`, não como check.
   Detalhes em [`docs/dependency-fingerprinting.md`](docs/dependency-fingerprinting.md).
   `webvigil.checks.disclosure` (spec 005): dois checks passivos (stack traces, directory
   listing) + um passo de sondagem opt-in no `Orchestrator` (`--probe` / `[disclosure]
   probe`, GET-only, sem portão Active) que testa um catálogo curado de paths sensíveis
   (`.git`, `.env`, backups, endpoints de debug) e alimenta seis checks probe-fed.
   Detalhes em [`docs/information-disclosure.md`](docs/information-disclosure.md).
   `webvigil.checks.injection` (spec 006): os primeiros checks `ACTIVE` — reflected XSS,
   SQLi (error/boolean/time), path traversal, open redirect. O `Orchestrator` roda um passo
   `InjectionScanner` (enumera injection points a partir de query params + `<form>`s
   parseados dos corpos já baixados, baseline por ponto, detectores sob um orçamento de
   requests compartilhado); seis checks finos viram findings a partir de
   `ctx.observations.injection_hits`. Portão `--mode active --authorized-by`; só GET/POST;
   detecção in-band (sem browser headless, sem coletor OAST). `[injection]` afina orçamento
   e time-based. Detalhes em [`docs/active-injection.md`](docs/active-injection.md).
   `webvigil.checks.csrf` (spec 007): um check passivo — `csrf.form.no-token` marca form
   `POST` state-changing sem token anti-CSRF, confiança ponderada pelo `SameSite` do cookie
   de sessão. Lê `ScanContext.forms` (o crawler agora parseia `<form>`s durante `discover()`
   e submete forms `GET` seguros para ampliar a superfície). Scan autenticado por cookie
   estático: `--cookie "name=value"` / `[auth] cookies`, anexado só a requests do host alvo,
   nunca em relatório/log/metadata; `webvigil.crawler.safety` guarda o crawl de links
   logout/destrutivos. Detalhes em [`docs/authenticated-scanning.md`](docs/authenticated-scanning.md).
4. **Reporting** (`webvigil.reporting`) — JSON (canônico), SARIF 2.1.0, HTML (Jinja2), Markdown.
5. **Persistência** (só Web, `webvigil.api.db`) — SQLite via SQLModel + Alembic; scans
   executados por um `ScanRunner` in-process (1 por vez, fila).
6. **Web UI** (`web/`) — dashboard Next.js (App Router). Cliente fino da Web API: nunca fala
   com o engine, não guarda estado além do cache do TanStack Query. Tipos gerados de
   `openapi.json` (`scripts/dump-openapi.py` → `pnpm gen:api`). O servidor Next faz proxy de
   `/api/*` para a API (mesma origem, sem CORS); `API_PROXY_TARGET` é lido só no
   `next.config` (assado no build). Detalhes em [`docs/web-ui.md`](docs/web-ui.md).

Regras: o engine (`core`, `http`, `crawler`, `checks`, `reporting`) nunca importa Typer,
Rich, FastAPI, SQLModel, Alembic, pyjwt nem argon2 — contrato verificado por `import-linter`
no CI. `webvigil.cli` e `webvigil.api` não se importam. A Web UI só fala com a API.

## Segurança / ética

- Safe Mode (`PASSIVE`) é o padrão e é seguro para produção.
- Active Mode exige `--mode active` **e** `--authorized-by`; sempre restrito ao escopo do host alvo.
- Política de boa vizinhança sempre ativa: cap de concorrência, delay, limite de páginas, scope guard.

## Fluxo de trabalho

- **Spec-driven development** via `/spec`. Specs em `specs/NNN-nome/` (requirements → design → tasks → implementação), com portão de aprovação humana em cada fase. Convenções e roadmap em [`specs/README.md`](specs/README.md).
- Estado: `001-foundation` (CLI `v0.1`), `002-web-api` (API `v0.2`), `003-web-ui` (dashboard `v0.3`), `004-deps-fingerprint` (`v0.4`), `005-info-disclosure` (`v0.5`), `006-active-injection` (`v0.6`) e `007-auth-flows` (`v0.7`) **concluídas**. Nenhuma spec em andamento. As próximas três (`008`–`010` no roadmap) tratam de dívidas técnicas já identificadas, atacáveis em qualquer ordem: `008-stored-xss` (crawl stateful de duas fases sobre o modelo de injection point da 006), `009-ssrf` (coletor OAST opt-in) e `010-osv-online` (provider OSV.dev online para o fingerprint de dependências da 004, hoje só Retire.js vendorado). A 007 entregou só cookie estático + CSRF passivo + submissão de forms GET; login automático, auth por header e testes de sessão saíram para uma spec futura.
- Ao fim de cada sessão: `/preparar-commits` (Conventional Commits) e `/atualizar-docs`.
- Commits em inglês, padrão Conventional Commits.
