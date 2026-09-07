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
| [`008-stored-xss`](008-stored-xss/) | stored/persistent XSS: passada `StoredXssScanner` em duas fases (injeta marcadores `<wvstored…>` nos injection points da `006`, depois um re-crawl de 1 hop procurando o marcador renderizado sem escape noutra página); Active Mode + opt-in `--stored-xss` (grava dados no alvo) | `v0.8` | **done** |
| `009-ssrf` | SSRF com coletor out-of-band opt-in: um serviço que o scanner hospeda e o alvo chama de volta (DNS/HTTP callback), habilitado explicitamente; cobre casos cegos que a detecção in-band não pega | `v0.9` | não iniciada |
| [`010-osv-online`](010-osv-online/) | provider OSV.dev online para o fingerprint de dependências da `004`: passo `_osv_lookup` no orquestrador (opt-in `--osv-online` / `[deps] osv_online`) que faz um `querybatch` + um `query` por pacote na `api.osv.dev`, normaliza pro `Advisory` nativo e mescla com o match Retire.js offline (dedup por identificador); falha vira warning, sem cache | `v0.10` | **done** |

> A 002 foi dividida: `002-web-api` (backend) e `003-web-ui` (Next.js). O roadmap
> original tratava as duas como uma spec só; as demais foram renumeradas.
>
> **`008`–`010` eram as três dívidas técnicas acumuladas**, atacáveis em qualquer ordem.
> `008-stored-xss` **entregou** (`v0.8`): a passada em duas fases relê páginas via um
> re-crawl de 1 hop, atrás do marcador que ela mesma gravou (opt-in `--stored-xss`, porque
> escreve dados no alvo). `010-osv-online` **entregou** (`v0.10`): o follow-up prometido da
> `004` — um provider OSV.dev online, opt-in (`--osv-online`), que amplia a cobertura do
> match Retire.js offline. Resta `009-ssrf` (linha original da `006`) — cruza a fronteira do
> "o engine só fala com o alvo" com egress explícito para um coletor OAST próprio, opt-in.
>
> **Login automático, auth por header e testes de sessão** (fixation, invalidação no
> logout, id fraco) estavam na linha original da `007`; saíram para uma spec futura — cada
> um exige o fluxo de login stateful ou Active Mode. A `007` entregou cookie estático +
> CSRF passivo + crawl de forms `GET`.
