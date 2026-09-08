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
   `OsvProvider` (spec 010): provider de advisory online opt-in (`--osv-online` /
   `[deps] osv_online`, default off) — único ponto do engine que fala com host que não é o
   alvo. Um passo `_osv_lookup` no `Orchestrator` (depois do fingerprint) faz um
   `POST /v1/querybatch` + um `POST /v1/query` por pacote com match na `api.osv.dev`, normaliza
   pro `Advisory` nativo e entrega via `ScanContext.observations`; o check mescla
   (`merge_advisories`, dedup por identificador) com o match offline. Falha de rede vira
   warning, não erro. Sem cache em disco.
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
   requests compartilhado); checks finos viram findings a partir de
   `ctx.observations.injection_hits`. Portão `--mode active --authorized-by`; só GET/POST;
   detecção in-band (sem browser headless, sem coletor OAST). `[injection]` afina orçamento
   e time-based. `injection.ssrf.metadata` (CRITICAL) / `injection.ssrf.internal` (HIGH)
   (spec 009): SSRF **in-band** — um detector `ssrf` na mesma passada que envia payloads de
   URL e prova o fetch server-side pelo response do alvo (marcador de metadata de nuvem,
   assinatura de `file://`, banner de serviço interno, ou erro de conexão ecoando a URL).
   `is_urllike` prioriza params com cara de URL. Sem flag, sem config (payloads só leem).
   SSRF cega não está no roadmap — exige coletor OAST hospedado, o que cruza "o engine só
   fala com o alvo" e a distribuição repo-only; quem precisar pareia com um colaborador
   externo próprio. `injection.cmdi.os` (CRITICAL) / `injection.ssti` (HIGH) (spec 011):
   RCE server-side **in-band** — dois detectores novos na mesma passada. `cmdi` tem um
   estágio echo (quebra de shell + `echo <marcador>=$((a*b))` → produto calculado colado ao
   marcador, ausente do baseline) e um estágio time-based (`sleep`/`ping -n`, confirmado
   contra controle de delay 0, gate `[injection] time_based_cmdi` / `--no-time-based-cmdi`,
   default on, sub-orçamento de sleep compartilhado com `sqli-time`). `ssti` faz polyglot →
   assinatura de erro do engine, depois payloads aritméticos por engine → produto avaliado
   colado ao marcador; identifica o engine (`{{7*'7'}}` → `7777777` Jinja2, `49` Twig).
   `is_commandlike` prioriza params com nome de comando/template; o `_SHELL_NAMES` mais
   estrito destrava o set completo de echo e o estágio time-based do `cmdi`. Command
   injection cega (sem output, sem timing) fica de fora — mesmo motivo da SSRF cega.
   `_PER_POINT_REQUEST_CAP` subiu de 30 → 35 e `request_budget` de 500 → 600 (mais
   famílias de detector por ponto).
   `injection.crlf` (HIGH) / `injection.host-header` (MEDIUM) / `injection.xxe` (HIGH) /
   `http.methods.unsafe` (MEDIUM, `Category.HTTP` nova) (spec 012): request-envelope
   injection **in-band**. `crlf` é detector novo no `InjectionScanner` (payload `%0d%0a` →
   header/cookie/body injetado que o `httpx` parseia de volta, não reflexão de texto).
   `xxe` é detector opt-in (`[injection] xxe` / `--xxe`, default off, só POST points,
   re-envia o body como XML com entidade externa → assinatura de arquivo ou erro de parser).
   `host-header` + `http.methods.unsafe` vêm de uma passada nova `EnvelopeScanner`
   (`webvigil.checks.envelope`, modelo do `DisclosureProbe`) que re-pede uma amostra de URLs
   crawleadas com `Host`/`X-Forwarded-*` = `webvigil.invalid` (sentinela em URL absoluta /
   `Location` / `<base>` / canonical) e com `OPTIONS`/`TRACE` (XST, verbos perigosos
   anunciados). Nunca envia verbo destrutivo. XXE cega e HTTP request smuggling ficam fora
   (colaborador / raw socket). `TRACE` entrou em `_IDEMPOTENT`; `HttpClient.request` ganhou
   `content=`.
   `injection.xss.stored` (spec 008):
   passada `StoredXssScanner` separada
   (depois da refletida, opt-in `--stored-xss` / `[injection] stored_xss`, default off —
   grava marcadores `<wvstored…>` que o alvo mantém). Fase A injeta um marcador por injection
   point; Fase B faz um re-crawl de 1 hop (`Crawler.recrawl`) a partir da fronteira do 1º
   crawl e correlaciona por token. Location do finding = o injection point (fingerprint
   estável); página(s) de render vão na evidência. Detalhes em
   [`docs/active-injection.md`](docs/active-injection.md).
   `webvigil.checks.csrf` (spec 007): um check passivo — `csrf.form.no-token` marca form
   `POST` state-changing sem token anti-CSRF, confiança ponderada pelo `SameSite` do cookie
   de sessão. Lê `ScanContext.forms` (o crawler agora parseia `<form>`s durante `discover()`
   e submete forms `GET` seguros para ampliar a superfície). Scan autenticado por cookie
   estático: `--cookie "name=value"` / `[auth] cookies`, anexado só a requests do host alvo,
   nunca em relatório/log/metadata; `webvigil.crawler.safety` guarda o crawl de links
   logout/destrutivos. Detalhes em [`docs/authenticated-scanning.md`](docs/authenticated-scanning.md).
   `webvigil.checks.content` (spec 013, `Category.CONTENT` nova): dois checks passivos —
   `content.sri.missing` (subresource cross-origin sem `integrity`, MEDIUM) e `content.mixed`
   (página `https` puxando subrecurso `http://`, MEDIUM/LOW). `webvigil.checks.disclosure`
   ganhou `disclosure.session-id-in-url` (token de sessão / API key numa URL que o alvo
   produziu — link, form action, `Location`; MEDIUM) e `disclosure.private-ip` (IP RFC-1918 /
   loopback / link-local num corpo; LOW). Auth por header/bearer (spec 013): `--header
   "Name: Value"` / `[auth] headers`, mesma disciplina do cookie da 007 (só host alvo, nunca
   em relatório/log/metadata, não sobrescreve header que o caller setou). Import de OpenAPI
   (spec 013): `--openapi <path|url>` / `[scan] openapi` — `webvigil.crawler.openapi` parseia
   um doc JSON OpenAPI 3.x / Swagger 2.0 (só `$ref` locais, cycle guard), o orquestrador
   carrega antes do crawl (falha = fatal), URLs de operações GET viram seeds do `Crawler`
   (`extra_seeds=`), e query/path params + campos de body form-urlencoded viram
   `InjectionPoint`s (`source="openapi"` / `"openapi-path"`) via `enumerate_points`. JSON só,
   sem fuzz de folha de body JSON, GET/POST só. Detalhes em
   [`docs/api-scanning.md`](docs/api-scanning.md) e
   [`docs/content-checks.md`](docs/content-checks.md).
   `injection.ldap` (HIGH, CWE-90) / `injection.xpath` (HIGH, CWE-643) / `injection.ssi`
   (HIGH, CWE-97) (spec 014): três detectores novos na passada do `InjectionScanner`,
   forma do `sqli` — assinatura de erro do parser (LDAP/XPath) ou diretiva `#echo` avaliada
   (SSI), mais um diferencial (`two_sided_split` do `sqli`, extraído pra `detect/_diff.py`;
   `wider_then_same` pro result-set do LDAP). `ssi` só prova avaliação, nunca `#exec` /
   `#include`. `_PER_POINT_REQUEST_CAP` 35→38, `request_budget` 600→650.
   `webvigil.checks.upload` (spec 014, `Category.UPLOAD` nova): `upload.unrestricted`
   (CRITICAL→MEDIUM, CWE-434) de uma passada `UploadScanner` nova no orquestrador (modelo do
   `EnvelopeScanner`), opt-in `--file-upload` / `[injection] file_upload` (grava arquivos no
   alvo, sem cleanup — disciplina do `--stored-xss`). Sobe marcadores benignos (`<?php echo
   6*7;?>`, `<script>` HTML/SVG, spoof de extensão/content-type, nome `../`) por form de
   upload descoberto, busca de volta e prova in-band: executado, servido inline, ou escrito
   fora do diretório de upload. Um probe `PUT` de marcador no diretório de entrada — único
   verbo destrutivo, só sob o opt-in (a 012 recusava `PUT`; a 014 o reabre aqui).
   `HttpClient.request` ganhou `files=` (multipart). Fronteiras de cobertura ativa
   documentadas em [`docs/active-injection.md`](docs/active-injection.md) ("Coverage
   boundaries"): EL injection, `eval()`, NoSQLi, HPP, RFI, DOM XSS, cega/OAST, smuggling e
   testes que exigem login stateful ficam de fora.
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
- Estado: `001-foundation` (CLI `v0.1`), `002-web-api` (API `v0.2`), `003-web-ui` (dashboard `v0.3`), `004-deps-fingerprint` (`v0.4`), `005-info-disclosure` (`v0.5`), `006-active-injection` (`v0.6`), `007-auth-flows` (`v0.7`), `008-stored-xss` (`v0.8`), `009-ssrf` (SSRF in-band, `v0.9`), `010-osv-online` (`v0.10`), `011-rce-injection` (command injection + SSTI in-band, `v0.11`), `012-protocol-injection` (CRLF, host header, XXE opt-in, métodos HTTP, `v0.12`), `013-auth-and-api-surface` (auth por header/bearer, import OpenAPI, SRI / mixed content / session-id-in-URL / private-IP passivos, `v0.13`) e `014-file-upload` (LDAP / XPath / SSI injection + file upload opt-in, `v0.14`) **concluídas**. O roadmap de dívida técnica está zerado; a linha `011`–`014` de paridade com ZAP/Wapiti no recorte in-band está fechada. A `v1.0` (marco de conclusão do roadmap — seção "Scope and limitations" no README + descrição/topics do repo no GitHub) está entregue; não houve bump de versão do pacote (`version = "0.0.0"` mantido nos 14 marcos). **SSRF cega, command injection cega, XXE cega e HTTP request smuggling** ficam fora do roadmap — exigem coletor OAST ou raw socket, cruzam "o engine só fala com o alvo" e a distribuição repo-only. YAML no `--openapi` e fuzz de folha de body JSON são limites da `013`, não permanentes. Pendências ainda abertas, da 007: login automático, testes de sessão (cada uma exige fluxo de login stateful ou Active Mode). Nenhuma spec em andamento.
- Ao fim de cada sessão: `/preparar-commits` (Conventional Commits) e `/atualizar-docs`.
- Commits em inglês, padrão Conventional Commits.
