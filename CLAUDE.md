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

- **Engine/CLI:** Python 3.12+ (piso 3.12; o CI testa 3.12, 3.13, 3.14 e 3.15, a mais nova estável, e a imagem Docker usa a 3.15), `uv`, `httpx`, `pydantic` v2, `typer`+`rich`, `jinja2`,
  `cryptography`, `selectolax`.
- **Web API (extra `web`):** `fastapi`, `uvicorn`, `sqlmodel`+`alembic` (SQLite), `argon2-cffi`, `pyjwt`.
- **Web UI:** `web/` — Next.js 16 (App Router) + React 19 + TypeScript + Tailwind CSS v4 + shadcn/ui + TanStack Query, gerido por `pnpm` (Node 26; `engines` em `web/package.json`; a imagem do Node 26 não traz o `corepack`, então o `web/Dockerfile` instala o pnpm da versão do `packageManager` com `npm install -g`).
- **Qualidade:** `ruff` → `black` → `mypy` (strict) → `import-linter` → `pytest` (`asyncio_mode=auto`).

O que cada peça faz, por que foi escolhida contra a alternativa, e o que estudar: [`docs/stack.md`](docs/stack.md).

## Comandos

```bash
uv sync --all-extras
uv run ruff check .
uv run black --check .
uv run mypy src
uv run lint-imports      # contrato: engine não importa Typer/Rich/FastAPI/SQLModel/Alembic/pyjwt/argon2
uv run pytest
uv run pytest --cov       # per-file line + branch coverage of src/webvigil (the guard of issue #101)
# A suíte inteira leva ~10 min com cobertura (mais de 1500 testes). Specs novas seguem as regras de teste
# de specs/README.md ("Testes de uma spec"): lógica em unit, integração anexa a um scan compartilhado.
uv run webvigil scan <url>
uv run webvigil list-checks
uv run webvigil report <scan.json> --format html
uv build && uv run --no-project python scripts/check-package.py dist   # o pacote que o PyPI recebe (a checagem do job `package`)
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

**Lighthouse CI** (`.github/workflows/lighthouse.yml`, issue #63): audita o dashboard (mobile e desktop, 3 rodadas, mediana) a cada mudança em `web/`, na API ou na própria configuração, e à mão (`workflow_dispatch`, na branch que se quer medir). Sobe o que o e2e sobe (fixture na 9100, `webvigil-web` na 8100 com SQLite descartável, `next build` + `next start` na 3100) e faz o seed com `scripts/lighthouse-seed.py` (conta, login, um scan concluído: o id é sempre 1, e `/scans/1` está nos JSONs). `/login` é auditado à parte, sem cookie (logado, ele redireciona); o cookie da sessão vai nas páginas logadas como `--collect.settings.extraHeaders`. `/setup` não entra: só existe antes da primeira conta. Limites em `.github/lighthouse/{mobile,desktop}{,-login}.json`: **erro** para acessibilidade e boas práticas < 95, `color-contrast`, `unsized-images`, `target-size`, erro de console (também no `/login`: o layout `(auth)` pergunta `GET /api/setup`, que devolve `authenticated` com 200, em vez de `/api/auth/me`, que daria 401), CLS > 0,1 e peso > 500 KB; **aviso** para a nota de Performance. **Não é check obrigatório** da `main` (o Lighthouse varia em runner compartilhado); `@lhci/cli` fixado em 0.15.1 (Lighthouse 12.6.1) em `LHCI_VERSION`, e o Dependabot não vê um `npx`. Os números são comparação relativa; os reais só existem em produção. Ao criar uma página nova, inclua a rota nos JSONs (`tests/unit/test_lighthouse_config.py` guarda que toda URL é uma página real e que mobile e desktop auditam o mesmo).

**Windows no CI** (issue #225): o job `quality` roda a matriz `python-version` × `os` (Linux em `ubuntu-26.04`, Windows em `windows-2025`, rótulo fixo, nunca `windows-latest`). É a **única exceção** à regra do `ubuntu-26.04`: o pacote declara `Operating System :: OS Independent` e o CI testa o que o classifier afirma. Os checks do Linux mantêm os nomes `quality (3.12)` etc. (o ruleset `proteger-main` os exige); os do Windows são `quality (Windows, 3.12)` etc. e **não são obrigatórios**. `package`, `docker`, `web` e `compose` ficam só no Linux.

**CodeQL** (`.github/workflows/codeql.yml`): analisa `actions`, `javascript-typescript` e `python` em push e PR na `main` e 1x por semana (domingo 09:00 de São Paulo, para pegar queries novas). **pip-audit semanal** (`.github/workflows/pip-audit.yml`, #207): toda segunda 09:00 de São Paulo (e à mão), roda o `pip-audit` sobre o `uv.lock` inteiro (runtime, extras e grupos dev), porque o CI só roda em PR e o Dependabot nem sempre abre PR de correção. Run vermelho = CVE no lock; a resposta é a `/atualizar-dependencias`.

## Arquitetura (resumo)

Camadas, de cima para baixo:

1. **Interfaces** — CLI (`webvigil.cli`) e Web API (`webvigil.api`, extra `web`, entry point
   `webvigil-web`). Clientes finos do `Orchestrator`.
2. **Scan Engine** (`webvigil.core`) — biblioteca pura, sem dependência de UI nem de banco:
   `Orchestrator`, `Target`/escopo/política, HTTP layer (`webvigil.http`), crawler leve
   (`webvigil.crawler`), registry de checks, modelo de `Finding`/`Severity`. O cliente lê no
   máximo `[http] max_body_bytes` de cada resposta (10 MiB, depois de descomprimir) e o scan avisa
   quantas foram cortadas; cada requisição tem um prazo total, `[http] total_timeout_s` (60 s, do
   envio ao último byte), tratado como timeout. O alvo é um host com ponto, de um rótulo só
   (`http://app:8000/`, nome de serviço do Compose ou de cluster) ou um literal IPv4/IPv6
   (`core/target.py::is_valid_host`); num host sem domínio registrável o `--scope subdomains` age como
   `host`, e os payloads que põem o host em userinfo (`payloads.fill_host`) não saem para um alvo IPv6.
3. **Checks** (`webvigil.checks`) — plugins `PASSIVE`/`ACTIVE`, registrados por decorator +
   entry points. Contrato: `Check.run(ctx: ScanContext) -> list[Finding]`. O detalhe de cada
   check e dos passos do `Orchestrator` (fingerprint e Retire.js, OSV online, injeção ativa,
   scan autenticado, HAR, API scanning) está em [docs/checks-internals.md](docs/checks-internals.md):
   leia-o antes de mexer em `webvigil.checks`.
4. **Reporting** (`webvigil.reporting`) — JSON (canônico), SARIF 2.1.0, HTML (Jinja2), Markdown. Tudo que
   veio do site escaneado é texto não confiável: o Markdown o escreve como texto puro (metacaracteres
   escapados, evidência cercada por mais crases do que qualquer sequência interna) e só uma referência
   `http(s)` vira link, no HTML e no dashboard (`core/urls.py::is_http_url`; o provider OSV só guarda URL
   absoluta `http(s)`).
5. **Persistência** (só Web, `webvigil.api.db`) — SQLite via SQLModel + Alembic; scans
   executados por um `ScanRunner` in-process (1 por vez, fila). O login tem espera crescente após 5
   falhas (`api/throttle.py`, em memória, por cliente e por usuário) e trocar a senha encerra as
   outras sessões (o JWT carrega `iat` e é recusado se for anterior a `User.updated_at`). A tabela
   do throttle é limitada (10 mil chaves: a que falhou há mais tempo sai, e uma chave com mais de 128
   caracteres vira SHA-256), `LoginIn` tem teto (usuário 64, senha 256, como o setup) e um middleware
   ASGI (`api/body_limit.py`) recusa corpo acima de 1 MiB com `413`; o `scan_id` das rotas fica em
   `1..2**63-1` (`ScanId` em `api/deps.py`, `422` fora disso). Um `POST`/`PUT`/`PATCH`/`DELETE` com `Origin`
   que não seja o do próprio servidor (o `Host`, ou o `X-Forwarded-Host` do proxy do dashboard) nem esteja em
   `web.cors_origins` leva `403` (`api/origin_check.py`); sem `Origin` (curl, CLI) passa. Toda resposta de
   relatório manda `nosniff`, e a de HTML também `Content-Security-Policy: sandbox; default-src 'none';
   style-src 'unsafe-inline'`.
6. **Web UI** (`web/`) — dashboard Next.js (App Router). Cliente fino da Web API: nunca fala
   com o engine, não guarda estado além do cache do TanStack Query. Tipos gerados de
   `openapi.json` (`scripts/dump-openapi.py` → `pnpm gen:api`). O servidor Next faz proxy de
   `/api/*` para a API (mesma origem, sem CORS); `API_PROXY_TARGET` é lido só no
   `next.config` (assado no build). O `next.config.ts` manda cabeçalhos de segurança nas páginas e nos
   arquivos estáticos (`web/src/lib/security-headers.ts`: sem enquadramento, `nosniff`,
   `Referrer-Policy`, `Permissions-Policy`); `/api/*` não leva, porque o Next só faz proxy. As páginas
   levam também uma `Content-Security-Policy` com nonce por requisição (spec 022, `web/src/proxy.ts` +
   `web/src/lib/csp.ts`): scripts só com o nonce, `style-src` mantém `'unsafe-inline'` (o toast injeta
   `<style>`), `frame-src blob:` para o preview do relatório; o layout raiz é `force-dynamic`, então nenhuma
   página é pré-renderizada. Detalhes em [`docs/web-ui.md`](docs/web-ui.md); os tokens
   de design e a escala de severidade, em [`docs/web-ui-design.md`](docs/web-ui-design.md).

> **Cuidado:** o Next 16 é dono do `web/tsconfig.json` — reescreve `jsx` /
> `include` / `plugins` e re-indenta a cada `next build` / `next dev`. Está no
> `.prettierignore` por isso; não edite à mão esperando que fique.

Regras: o engine (`core`, `http`, `crawler`, `checks`, `reporting`) nunca importa Typer,
Rich, FastAPI, SQLModel, Alembic, pyjwt nem argon2 — contrato verificado por `import-linter`
no CI. `webvigil.cli` e `webvigil.api` não se importam. A Web UI só fala com a API.

## Segurança / ética

- Safe Mode (`PASSIVE`) é o padrão e é seguro para produção.
- Active Mode exige `--mode active` **e** `--authorized-by`; sempre restrito ao escopo do host alvo.
- Política de boa vizinhança sempre ativa: cap de concorrência, delay, limite de páginas, scope guard.

## Fluxo de trabalho

- **Spec-driven development** via `/spec`. Specs em `specs/NNN-nome/` (requirements → design → tasks → implementação), com portão de aprovação humana em cada fase. Convenções e roadmap em [`specs/README.md`](specs/README.md).
- Estado: `001-foundation` (CLI `v0.1`), `002-web-api` (API `v0.2`), `003-web-ui` (dashboard `v0.3`), `004-deps-fingerprint` (`v0.4`), `005-info-disclosure` (`v0.5`), `006-active-injection` (`v0.6`), `007-auth-flows` (`v0.7`), `008-stored-xss` (`v0.8`), `009-ssrf` (SSRF in-band, `v0.9`), `010-osv-online` (`v0.10`), `011-rce-injection` (command injection + SSTI in-band, `v0.11`), `012-protocol-injection` (CRLF, host header, XXE opt-in, métodos HTTP, `v0.12`), `013-auth-and-api-surface` (auth por header/bearer, import OpenAPI, SRI / mixed content / session-id-in-URL / private-IP passivos, `v0.13`) e `014-file-upload` (LDAP / XPath / SSI injection + file upload opt-in, `v0.14`) **concluídas**. O roadmap de dívida técnica está zerado; a linha `011`–`014` de paridade com ZAP/Wapiti no recorte in-band está fechada. A `v1.0` (marco de conclusão do roadmap — seção "Scope and limitations" no README + descrição/topics do repo no GitHub) está entregue; o pacote ficou em `version = "0.0.0"` durante os marcos e foi para `1.0.0` no release de 2026-10-08. **SSRF cega, command injection cega, XXE cega e HTTP request smuggling** ficam fora do roadmap — exigem coletor OAST ou raw socket, cruzam "o engine só fala com o alvo" e a distribuição repo-only. YAML no `--openapi` e fuzz de folha de body JSON são limites da `013`, não permanentes. `015-web-toolchain-modernization` (**concluída**) modernizou o toolchain do `web/`: Node 20 (EOL) → 24, Tailwind CSS 3 → 4 (+ `tailwind-merge` 3, `tw-animate-css`), Next.js 15 → 16 (+ `eslint-config-next` 16, `next lint` → `eslint` flat config, Turbopack). Sem mudança visual nem no engine. Veio junto com um reparo de CI (o job `web` estava vermelho havia 60+ runs: lockfile do Dependabot quebrado, fallout do vitest 4, e2e que nunca rodou no Linux). Fechou os PRs de version-update do Dependabot #7/#8/#10/#11. `016-el-injection` (**concluída**, issue #56, `v0.16`) adicionou `injection.el`: expression-language injection in-band (SpEL / OGNL / JEXL / MVEL / Unified EL), com o detector combinado `ssti+el` e `_PER_POINT_REQUEST_CAP` 38 → 42; `eval()` code injection ficou fora. `017-csrf-confirmation` (**concluída**, issue #54, `v0.17`) adicionou `csrf.form.token-not-enforced`: confirmação ativa do CSRF por controle + replays cross-site, opt-in `--confirm-csrf`, passada `CsrfScanner` que roda por último. `018-post-form-crawl` (**concluída**, issue #55, `v0.18`) deu ao crawler uma fase POST opt-in (`--submit-post-forms`, só Active Mode): submete forms candidatos e operações `POST` do `--openapi` com valores benignos e segue o que as respostas ligam. `019-automated-login` (**concluída**, issue #52, `v0.19`) deu ao engine um login automático por form (`--login-url`, só Active Mode, uma tentativa, sessão num jar do host alvo, re-login quando cai, senha só por env/prompt). `020-session-security` (**concluída**, issue #53, `v0.20`) adicionou `session.id.weak`, `session.fixation` e `session.logout.not-invalidated` (`Category.SESSION`): passada `SessionScanner` por último, evidência sem valores de cookie, amostragem anônima `--sample-sessions` e teste de logout `--test-logout` (só Active). O roadmap de pendências da 007 está zerado. `021-har-import` (**concluída**, issue #146, `v0.21`) adicionou `--har` (import de HAR para SPAs, descrito acima). `022-dashboard-csp` (**concluída**, issue #138 passo 2, `v0.22`) deu ao dashboard a CSP com nonce (descrita acima). Nenhuma spec em andamento.
- **Releases 1.0.0 a 1.1.0 (1.0.0 a 1.0.4 em 2026-10-08; 1.1.0 em 2026-10-09):** `webvigil` no PyPI, imagem `ghcr.io/ryanvmorais/webvigil` e GitHub Releases `v1.0.0` a `v1.1.0`; o plano da 1.0.0 está na issue #111, a 1.1.0 é a primeira minor (import de HAR, CSP do dashboard, alvo de um rótulo/IPv6, fuzz de `<select>`, prazo total por requisição, lote de endurecimento #161/#162/#163/#172) e as demais são patches: a 1.0.1 (endurecimento da Web API, backend Lexbor, correção do aviso `GHSA-vw64-75mj-x37q`), a 1.0.2, a 1.0.3 e a 1.0.4 (correções dos avisos `GHSA-wxvq-cw49-p7f6`, `GHSA-7cmg-mh2g-8rwv` e `GHSA-63j8-4f3v-r77j`, sobre texto e volume de dados vindos do site escaneado). Como cortar uma versão: [`docs/releasing.md`](docs/releasing.md) (Trusted Publishing, ensaio no TestPyPI, `release.yml`); a skill global `/preparar-release` conduz o processo, e o molde das notas do Release está no mesmo `docs/releasing.md`. O `web/openapi.json` carrega `info.version`: ao subir a versão, rode `uv run python scripts/dump-openapi.py` e `pnpm gen:api`. O engine usa o backend Lexbor do `selectolax` (`selectolax.lexbor`; o Modest foi removido na 1.0 e não volta); o que ficou para depois do 1.0 está na memória do projeto (`post-1-0-backlog`). O contrato de compatibilidade é [`docs/stability.md`](docs/stability.md) e toda mudança visível ao usuário entra em `[Unreleased]` do [`CHANGELOG.md`](CHANGELOG.md) **no mesmo PR**. O JSON do relatório tem `schema_version` (`SCHEMA_VERSION` em `core/result.py`): campo novo mantém, remover/renomear/retipar sobe a versão (e é major). Publicar é ato do Ryan; eu preparo o material.
- Ao fim de cada sessão: `/atualizar-docs` e depois `/fechar-sessao` (agrupa, commita em Conventional Commits numa branch, dá push, abre/atualiza o PR — para antes do merge).
- Commits em inglês, padrão Conventional Commits.
