# Specs

WebVigil is built with spec-driven development. Each feature is designed as a spec under
`specs/NNN-nome/` before implementation, driven by the `/spec` skill.

## Convenções

- **Numeração:** `NNN` sequencial de três dígitos (`001`, `002`, …), na ordem em que as
  specs são abertas. O nome é curto e em inglês (`001-foundation`).
- **Arquivos:** cada spec tem `requirements.md` (o quê / porquê), `design.md` (como) e
  `tasks.md` (quebra executável). Cada um com frontmatter `feature / status / date /
  related / origin`.
- **Fases e portões:** `requirements → design → tasks → implementação`. Cada fase termina
  com aprovação humana explícita antes de avançar.
- **Status válidos:** `draft` → `approved` → `in progress` → `done`. (`origin: conception`
  para specs escritas antes da implementação; `reverse-engineering` só para documentar
  algo já finalizado.)
- **Rastreabilidade:** requisitos são `RF-NN` (funcionais) e `RNF-NN` (não-funcionais);
  cada tarefa e decisão de design cita o(s) requisito(s) que satisfaz.
- **Idioma:** specs em inglês (regra do projeto). A conversa com o Ryan segue em português.

## Roadmap

| Spec | Escopo | Entrega | Status |
|---|---|---|---|
| [`001-foundation`](001-foundation/) | Engine puro, contrato de check + registry, HTTP layer + scope guard, crawler, `Finding`/`Severity`, Safe/Active mode + portão de autorização, reporters (JSON/SARIF/HTML/MD), CLI, checks v0.1 (headers/cookies/TLS/CORS), CI, Dockerfile | CLI `v0.1` | **done** |
| [`002-web-api`](002-web-api/) | FastAPI + SQLite (SQLModel + Alembic) + auth single-user (setup na 1ª execução) + execução async de scan com fila 1-a-1 + endpoints de export | API `v0.2` | **done** |
| [`003-web-ui`](003-web-ui/) | dashboard Next.js (App Router + Tailwind + shadcn/ui + TanStack Query) consumindo a API da 002: setup/login, lista de scans, novo scan, detalhe com findings, preview/export de relatório, catálogo de checks, settings | Web UI `v0.3` | **done** |
| [`004-deps-fingerprint`](004-deps-fingerprint/) | fingerprint passivo de libs JS no front + match com base Retire.js vendorada (offline); inventário de tecnologias no resultado, relatórios, API e dashboard | `v0.4` | **done** |
| [`005-info-disclosure`](005-info-disclosure/) | stack traces e directory listing (passivo) + sondagem opt-in (`--probe`) de `.git`/`.env`/backups/endpoints de debug com catálogo curado e validação de conteúdo; só engine (sem mudança na API/UI) | `v0.5` | **done** |
| [`006-active-injection`](006-active-injection/) | Active Mode: XSS refletido, SQLi (error/boolean/time), path traversal, open redirect; descoberta de forms + injection points; passo de fuzzing com orçamento; app-alvo vulnerável (fixture + serviço compose) | `v0.6` | **done** |
| [`007-auth-flows`](007-auth-flows/) | scan autenticado por cookie estático (`--cookie` / `[auth]`), check CSRF passivo (`csrf.form.no-token`, ponderado por SameSite), crawl que submete forms `GET` seguros + heurística de evasão de links logout/destrutivos | `v0.7` | **done** |
| — | dívidas técnicas: SSRF (coletor OAST opt-in), Stored XSS (crawl stateful de duas fases), provider OSV.dev online para a spec 004 | — | não iniciada |

> A 002 foi dividida: `002-web-api` (backend) e `003-web-ui` (Next.js). O roadmap
> original tratava as duas como uma spec só; as demais foram renumeradas.
>
> **Stored XSS e SSRF** estavam na linha original da `006`; saíram para uma spec futura.
> Stored XSS exige um crawl stateful de duas fases; SSRF exige um coletor out-of-band, que
> conflita com o princípio "o engine só fala com o alvo" (spec 004/005). A `006` entregou
> as quatro classes detectáveis in-band.
>
> **Login automático, auth por header e testes de sessão** (fixation, invalidação no
> logout, id fraco) estavam na linha original da `007`; saíram para uma spec futura — cada
> um exige o fluxo de login stateful ou Active Mode. A `007` entregou cookie estático +
> CSRF passivo + crawl de forms `GET`.
