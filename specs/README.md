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
- **Status válidos:** `planned` → `draft` → `approved` → `in progress` → `done`.
  (`planned`: entrada de roadmap, sem arquivos de spec ainda. `origin: conception` para
  specs escritas antes da implementação; `reverse-engineering` só para documentar algo já
  finalizado.)
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
| [`009-ssrf`](009-ssrf/) | SSRF **in-band**: um detector `ssrf` na passada da `006` que envia payloads de URL e prova o fetch server-side pelo response do alvo — marcador de metadata de nuvem (`injection.ssrf.metadata`, CRITICAL), assinatura de `file://` / banner de serviço interno / erro de conexão ecoando a URL (`injection.ssrf.internal`, HIGH). `is_urllike` prioriza params com cara de URL; sem flag, sem config. SSRF cega adiada | `v0.9` | **done** |
| [`010-osv-online`](010-osv-online/) | provider OSV.dev online para o fingerprint de dependências da `004`: passo `_osv_lookup` no orquestrador (opt-in `--osv-online` / `[deps] osv_online`) que faz um `querybatch` + um `query` por pacote na `api.osv.dev`, normaliza pro `Advisory` nativo e mescla com o match Retire.js offline (dedup por identificador); falha vira warning, sem cache | `v0.10` | **done** |
| [`011-rce-injection`](011-rce-injection/) | injeção server-side in-band que faltava na passada da `006`: OS command injection (echo aritmético + time-based, `injection.cmdi.os` CRITICAL) e SSTI (polyglot → assinatura de erro → avaliação aritmética, `injection.ssti` HIGH). Dois detectores novos no `InjectionScanner`, `[injection] time_based_cmdi`, fixture `/ping` + `/greet` | `v0.11` | **done** |
| [`012-protocol-injection`](012-protocol-injection/) | request-envelope injection in-band: `injection.crlf` (HIGH — header/body split que o `httpx` parseia de volta), `injection.host-header` (MEDIUM/HIGH — sentinela refletida em URL absoluta/`Location`/`<base>`), `injection.xxe` (HIGH, opt-in `--xxe` — content-type flip nos POST points), `http.methods.unsafe` (MEDIUM, `Category.HTTP` — XST + verbos perigosos anunciados). Detectores `crlf`/`xxe` no `InjectionScanner`; passada nova `EnvelopeScanner` pra host-header + métodos | `v0.12` | **done** |
| [`013-auth-and-api-surface`](013-auth-and-api-surface/) | largura de auth + superfície de API: auth por header/bearer (`--header "Name: Value"` / `[auth] headers`, mesma disciplina de segredo do cookie da `007`), import de OpenAPI 3.x / Swagger 2.0 JSON (`--openapi <path\|url>`) que semeia o crawl (URLs de operações GET → `Crawler.extra_seeds`) e a passada de injeção (query / path / campos de body form-urlencoded → `enumerate_points`, `source="openapi"`), e quatro checks passivos: `content.sri.missing`, `content.mixed` (`Category.CONTENT` nova), `disclosure.session-id-in-url`, `disclosure.private-ip`. Sem dependência nova; JSON só; sem fuzz de folha de body JSON; GET/POST só | `v0.13` | **done** |
| [`014-file-upload`](014-file-upload/) | **opcional / backlog:** detecção de upload sem restrição (extensão / content-type / conteúdo servido de volta) + checks ativos residuais. A `v1.0` pode sair após a `013` se a `014` não se justificar | `v0.14` | **planned** |

> A 002 foi dividida: `002-web-api` (backend) e `003-web-ui` (Next.js). O roadmap
> original tratava as duas como uma spec só; as demais foram renumeradas.
>
> **`008` a `010` eram as três dívidas técnicas acumuladas**, atacáveis em qualquer ordem —
> **todas entregues**. `008-stored-xss` (`v0.8`): passada em duas fases com re-crawl de 1
> hop atrás do marcador que ela mesma gravou (opt-in `--stored-xss`). `010-osv-online`
> (`v0.10`): provider OSV.dev online opt-in (`--osv-online`), follow-up da `004`.
> `009-ssrf` (`v0.9`): SSRF **in-band** — recorte deliberado, sem coletor OAST, sem custo,
> sem infra.
>
> **SSRF cega não está no roadmap.** Detectá-la exige um coletor out-of-band (OAST) — um
> servidor que o scanner hospeda, com domínio público e portas DNS/HTTP — que cruza o
> princípio "o engine só fala com o alvo" e a decisão de distribuir a ferramenta só pelo
> repositório, sem serviço hospedado. Quem precisar cobrir o caso cego pareia a WebVigil
> com um colaborador externo próprio (Burp Collaborator, interactsh). Um dia isso pode
> virar uma spec *bring-your-own-collaborator* (a WebVigil dispara payloads para um domínio
> que você passa, sem hospedar nem armazenar nada) — não planejada.
>
> **Login automático e testes de sessão** (fixation, invalidação no logout, id fraco)
> estavam na linha original da `007`; seguem numa spec futura — cada um exige o fluxo de
> login stateful ou Active Mode. A `007` entregou cookie estático + CSRF passivo + crawl de
> forms `GET`. **Auth por header/bearer foi agendada na `013`** (não precisa de login
> stateful).
>
> **`011` a `014` são a linha de "paridade real" com ZAP/Wapiti** no recorte que a WebVigil
> se propõe a cobrir: as classes de injeção que um revisor notaria faltando (command
> injection, SSTI, CRLF, host header, XXE, upload) e a largura mínima de auth/API. Todas
> **in-band, sem browser, sem OAST**. A `011` (command injection + SSTI), a `012` (CRLF,
> host header, XXE opt-in, métodos HTTP) e a `013` (auth por header, import OpenAPI, quatro
> checks passivos) **estão entregues**; só a `014` (file upload, opcional) fica antes da
> `v1.0`. Os não-objetivos abaixo continuam valendo e viram a seção "Scope and limitations"
> do README na `v1.0`:
>
> - **Crawl de SPA renderizada em JS** — sem browser headless; escaneie a API direto (a
>   `013` importa OpenAPI) ou alimente URLs de um crawler seu.
> - **Blind / OAST** (blind XSS/SSRF/RCE, XXE OOB) e **HTTP request smuggling** — ver
>   [`docs/notes/why-not-oast.md`](../docs/notes/why-not-oast.md).
> - **OpenAPI em YAML** e **fuzz campo a campo de body JSON** — limites da `013` (JSON só,
>   sem dependência nova; params de query / path / body form-urlencoded são fuzzados), não
>   permanentes.
> - **Base de templates estilo Nuclei**, fuzzing exaustivo, enum de CMS, brute-force de login.
>
> Sequência: `011` → `012` → `013` (feitas) → (`014` se valer) → `v1.0` (README "Scope and
> limitations" + descrição no GitHub).
