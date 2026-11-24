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

## Stack

- **Engine/CLI:** Python 3.12+ (piso 3.12; o CI testa 3.12, 3.13, 3.14 e 3.15, a mais nova estável, e a imagem Docker usa a 3.15), `uv`, `httpx2`, `certifi`, `pydantic` v2, `typer`+`rich`, `jinja2`,
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
uv run lint-imports      # contrato: engine não importa Typer/Rich/FastAPI/SQLModel/Alembic/pyjwt/argon2/Uvicorn
uv run pytest
uv run pytest --cov       # per-file line + branch coverage of src/webvigil (the guard of issue #101)
# A suíte inteira leva ~1,5 min com cobertura (cerca de 3200 testes; os scans de integração zeram o backoff
# de retry do cliente, que custava ~3 s por sonda 5xx: #307). Specs novas seguem as regras de teste
# de specs/README.md ("Testing a spec"): lógica em unit, integração anexa a um scan compartilhado.
uv run webvigil scan <url>
uv run webvigil list-checks
uv run webvigil report <scan.json> --format html
uv build && uv run --no-project python scripts/check-package.py dist   # o pacote que o PyPI recebe (a checagem do job `package`)
uv run webvigil-web serve            # Web API (extra `web`) — /docs em http://127.0.0.1:8000
uv run webvigil-web migrate
uv run python scripts/dump-openapi.py  # regenera web/openapi.json após mudar a API
uv run python scripts/update-retirejs-db.py  # atualiza a base Retire.js vendorada (spec 004)
uv run python scripts/update-public-suffix-list.py  # atualiza a Public Suffix List vendorada (--scope subdomains)
uv run python scripts/tidy-demo-svg.py assets/cli-scan-demo.svg  # alinha a gravação do README à grade (depois do svg-term)
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

**Lighthouse CI** (`.github/workflows/lighthouse.yml`, issue #63): audita o dashboard (mobile e desktop, 3 rodadas, mediana) a cada mudança em `web/`, na API ou na própria configuração, e à mão (`workflow_dispatch`, na branch que se quer medir). Sobe o que o e2e sobe (fixture na 9100, `webvigil-web` na 8100 com SQLite descartável, `next build` + `next start` na 3100) e faz o seed com `scripts/lighthouse-seed.py` (conta, login, um scan concluído: o id é sempre 1, e `/scans/1` está nos JSONs). `/login` é auditado à parte, sem cookie (logado, ele redireciona); o cookie da sessão vai nas páginas logadas como `--collect.settings.extraHeaders`. `/setup` não entra: só existe antes da primeira conta. Limites em `.github/lighthouse/{mobile,desktop}{,-login}.json`: **erro** para acessibilidade e boas práticas < 95, `color-contrast`, `unsized-images`, `target-size`, erro de console (também no `/login`: o layout `(auth)` pergunta `GET /api/setup`, que devolve `authenticated` com 200, em vez de `/api/auth/me`, que daria 401), CLS > 0,1 e peso > 500 KB; **aviso** para a nota de Performance. **Não é check obrigatório** da `main` (o Lighthouse varia em runner compartilhado); `@lhci/cli` fixado em 0.16.0 (Lighthouse 13.6.0) em `LHCI_VERSION`, e o Dependabot não vê um `npx`. Os números são comparação relativa; os reais só existem em produção. Ao criar uma página nova, inclua a rota nos JSONs (`tests/unit/test_lighthouse_config.py` guarda que toda URL é uma página real, que mobile e desktop auditam o mesmo e o nível e o limite de cada portão).

**Windows no CI** (issue #225): o job `quality` roda a matriz `python-version` × `os` (Linux em `ubuntu-26.04`, Windows em `windows-2025`, rótulo fixo, nunca `windows-latest`). É a **única exceção** à regra do `ubuntu-26.04`: o pacote declara `Operating System :: OS Independent` e o CI testa o que o classifier afirma. Os checks do Linux mantêm os nomes `quality (3.12)` etc. (o ruleset `proteger-main` os exige); os do Windows são `quality (Windows, 3.12)` etc. e **não são obrigatórios**. `package`, `docker`, `web` e `compose` ficam só no Linux.

**CodeQL** (`.github/workflows/codeql.yml`): analisa `actions`, `javascript-typescript` e `python` em push e PR na `main` e 1x por semana (domingo 09:00 de São Paulo, para pegar queries novas). **pip-audit semanal** (`.github/workflows/pip-audit.yml`, #207): toda segunda 09:00 de São Paulo (e à mão), roda o `pip-audit` sobre o `uv.lock` inteiro (runtime, extras e grupos dev), porque o CI só roda em PR e o Dependabot nem sempre abre PR de correção. Run vermelho = CVE no lock; a resposta é subir o `uv.lock` para a versão corrigida.

## Arquitetura (resumo)

Camadas, de cima para baixo:

1. **Interfaces** — CLI (`webvigil.cli`) e Web API (`webvigil.api`, extra `web`, entry point
   `webvigil-web`). Clientes finos do `Orchestrator`.
2. **Scan Engine** (`webvigil.core`) — biblioteca pura, sem dependência de UI nem de banco:
   `Orchestrator`, `Target`/escopo/política, HTTP layer (`webvigil.http`), crawler leve
   (`webvigil.crawler`), registry de checks, modelo de `Finding`/`Severity`. O cliente lê no
   máximo `[http] max_body_bytes` de cada resposta (10 MiB, depois de descomprimir, em cada etapa:
   o engine decodifica `gzip`/`deflate` sozinho em `http/decoding.py`) e o scan avisa quantas foram
   cortadas; cada requisição tem um prazo total, `[http] total_timeout_s` (60 s, do envio ao último
   byte, sem repetição), e o scan inteiro tem `[scan] max_duration_s` (4 h, `--max-duration`). O
   alvo é um host com ponto, de um rótulo só (`http://app:8000/`, nome de serviço do Compose ou de
   cluster) ou um literal IPv4/IPv6 (`core/target.py::is_valid_host`); o domínio registrável do
   `--scope subdomains` vem da Public Suffix List vendorada em `core/data/` (seções ICANN e
   privada), e num host sem domínio registrável (um rótulo, IP ou o próprio sufixo público) ele age
   como `host`; os payloads que põem o host em userinfo (`payloads.fill_host`) não saem para um
   alvo IPv6.
   O escopo confere também a porta (a do alvo, mais o par 80/443 se o alvo usa a padrão) e as
   credenciais só vão à origem do alvo ou ao upgrade `https` (`Target.carries_credentials`). Cada
   nome resolve uma vez por scan e a conexão vai ao IP conferido (`http/addresses.py`, instalado no
   transporte do `httpx2` para não perder o proxy do ambiente); alvo público não chega a IP interno.
   A confiança de certificados é do engine (`http/tls.py`): `certifi`, ou `SSL_CERT_FILE` /
   `SSL_CERT_DIR`, e a conexão com um proxy `https://` confia também no repositório do sistema.
   ⚠️ Todo cliente novo passa `verify=client_ssl_context()` e chama `pin_proxy_trust`, nunca o
   `verify=True` da biblioteca.
   Todo campo de texto livre do resultado tem teto (`core/bounded.py`: `Name` 1 Ki caracteres,
   `Text` 16 Ki, `Url` 64 Ki, evidência 4 Ki), cortado com `...[truncated]` na criação e na
   leitura, sem recusar; o `webvigil report` lê no máximo 256 MiB (`MAX_REPORT_BYTES`), exige
   `schema_version` inteiro e recalcula as contagens a partir dos achados.
3. **Checks** (`webvigil.checks`) — plugins `PASSIVE`/`ACTIVE`, registrados por decorator +
   entry points. Contrato: `Check.run(ctx: ScanContext) -> list[Finding]`. O detalhe de cada
   check e dos passos do `Orchestrator` (fingerprint e Retire.js, OSV online, injeção ativa,
   scan autenticado, HAR, API scanning) está em [docs/checks-internals.md](docs/checks-internals.md):
   leia-o antes de mexer em `webvigil.checks`.
4. **Reporting** (`webvigil.reporting`) — JSON (canônico), SARIF 2.1.0, HTML (Jinja2), Markdown. Tudo que
   veio do site escaneado é texto não confiável: o Markdown o escreve como texto puro (metacaracteres
   escapados, evidência cercada por mais crases do que qualquer sequência interna, célula de tabela sem
   code span, menção/`#n`/URL nua quebradas com `&#8203;`) e só uma referência `http(s)` vira link, no
   Markdown, no HTML e no dashboard (`core/urls.py::is_http_url`, espelhado em `web/src/lib/links.ts`; o
   provider OSV só guarda URL absoluta `http(s)`). Caractere de controle vira `\xNN` e bidi/largura zero
   (`INVISIBLE_CHARS`) vira `\uNNNN` visível (`core/text.py::show_controls`, espelhado em
   `web/src/lib/text.ts`) no resumo do terminal, nas linhas de erro, no Markdown, no HTML e no dashboard,
   e escape `\uNNNN` no JSON; o SARIF escapa `[`/`]` na mensagem. O resumo
   (`cli/_render.py`) nunca interpreta texto de achado ou aviso como marcação do Rich (`Text` por partes).
5. **Persistência** (só Web, `webvigil.api.db`) — SQLite via SQLModel + Alembic; scans executados
   por um `ScanRunner` in-process (1 por vez, fila). O login tem espera crescente após 5 falhas
   (`api/throttle.py`, em memória), que é só do cliente que errou; um limite curto por usuário (20
   em 30 s) contém palpites espalhados por muitos endereços, e só 4 checagens Argon2 rodam ao mesmo
   tempo (o excesso leva `429` com `Retry-After`). O cliente é o endereço da conexão, ou o
   `X-Forwarded-For` só quando a conexão vem de um proxy de `web.trusted_proxies`
   (`api/client_address.py`; o Compose confia só no dashboard). Trocar a senha encerra as outras
   sessões (o JWT carrega `iat` e é recusado se for anterior a `User.updated_at`). A tabela do
   throttle é limitada (10 mil chaves: sai a que falhou há mais tempo entre as que não estão
   esperando, e uma chave com mais de 128 caracteres vira SHA-256), `LoginIn` tem teto (usuário 64,
   senha 256, como o setup) e um middleware ASGI (`api/body_limit.py`) recusa corpo acima de 1 MiB
   com `413`; o `scan_id` das rotas fica em
   `1..2**63-1` (`ScanId` em `api/deps.py`, `422` fora disso). Antes de tudo, `api/host_check.py` recusa com `400` um `Host` ou `X-Forwarded-Host` que não seja IP, `localhost`, o `host` do bind ou um nome de `web.allowed_hosts` (o Compose lista `api`); o throttle do login confere e conta a tentativa num passo só, com trava, e o setup inicial cria uma conta só. Um `POST`/`PUT`/`PATCH`/`DELETE` com `Origin`
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
Rich, FastAPI, SQLModel, Alembic, pyjwt, argon2 nem Uvicorn — contrato verificado por `import-linter`
no CI. `webvigil.cli` e `webvigil.api` não se importam. A Web UI só fala com a API.

## Segurança / ética

- Safe Mode (`PASSIVE`) é o padrão e é seguro para produção.
- Active Mode exige `--mode active` **e** `--authorized-by`; sempre restrito ao escopo do host alvo.
- Política de boa vizinhança sempre ativa: cap de concorrência, delay, limite de páginas, scope guard.

## Fluxo de trabalho

- **Spec-driven development.** Specs em `specs/NNN-nome/` (requirements → design → tasks → implementação), com portão de aprovação humana em cada fase. Convenções e roadmap em [`specs/README.md`](specs/README.md).
- Estado: as specs `001` a `023` estão **concluídas** e nenhuma está em andamento; escopo, issue e entrega de cada uma na tabela "Roadmap" do [`specs/README.md`](specs/README.md), e o que cada versão trouxe no [`CHANGELOG.md`](CHANGELOG.md). Os limites (detecção cega/OAST, request smuggling, YAML no `--openapi`) estão em "Scope and limitations" do [`README.md`](README.md).
- **Releases:** PyPI, `ghcr.io/ryanvmorais/webvigil` e GitHub Releases desde a `v1.0.0`. Como cortar uma versão e o molde das notas: [`docs/releasing.md`](docs/releasing.md); compatibilidade: [`docs/stability.md`](docs/stability.md). ⚠️ Toda mudança visível ao usuário entra em `[Unreleased]` do [`CHANGELOG.md`](CHANGELOG.md) **no mesmo PR**. ⚠️ Ao subir a versão, rode `uv run python scripts/dump-openapi.py` e `pnpm gen:api` (o `web/openapi.json` carrega `info.version`). ⚠️ `schema_version` (`SCHEMA_VERSION` em `core/result.py`): campo novo mantém; remover, renomear ou retipar sobe a versão e é major. O engine usa só o backend Lexbor do `selectolax` (`selectolax.lexbor`). Publicar uma versão é ato do mantenedor.
- Commits em inglês, padrão Conventional Commits.
