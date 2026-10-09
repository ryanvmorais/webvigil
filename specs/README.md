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

## Testes de uma spec

Regra nascida da auditoria da suíte (issue #101): 1062 testes e horas de integração viraram
876 testes e ~10 min, sem perder uma linha nem um branch coberto. Toda spec nova segue isto no
`design.md` (seção de testes) e no `tasks.md`:

1. **A lógica se testa em unit.** Detector, veredito, tabela de payloads, predicado de
   segurança e parser são testados chamando a função com entradas montadas, sem scan.
2. **Integração anexa a um scan compartilhado.** `tests/integration/test_scan_fixture_app.py`
   roda **uma vez por configuração** (a fixture `scan` guarda o resultado na sessão). Um cenário
   novo lê o resultado de um scan existente; se precisa de uma opção nova, ela entra no scan com
   tudo ligado (`_full(profile)`), não num scan novo. Scan novo só quando a configuração é
   incompatível (ex.: `hardened`, ou um opt-in que muda o que os outros testes esperam).
3. **Rota de fixture só para invariante de segurança.** Teste de `tests/fixtures/` que apenas
   repete a resposta de uma rota é dispensável: o scan de integração já prova que a página é
   alcançada. Ficam os que guardam uma garantia (o avaliador `ast` nunca chega a `eval`, a rota
   endurecida recusa o replay).
4. **Determinismo se testa uma vez.** `test_full_scan_is_deterministic` compara todos os
   findings do scan completo; spec nova não ganha o seu próprio teste de determinismo
   (`scan.fresh(...)` existe para esse teste e para mais nenhum).
5. **Tabela em vez de cópia.** Mesma asserção sobre N flags/checks/formatos = um teste
   parametrizado ou dirigido pelo registry. Todo check novo ganha **uma linha** em
   `tests/unit/test_check_metadata.py` (id, categoria, modo, severidade, CWEs), não um teste
   de constantes próprio.
6. **Invariantes de segurança continuam testadas**, cada uma em pelo menos um teste: Passive não
   envia request forjado nem `POST`; passadas de CSRF / crawl POST nunca mandam payload; opt-in
   fora do Active Mode avisa e não faz nada; cookies e headers configurados nunca chegam a um
   relatório; página de `POST` nunca é re-pedida com `GET`.
7. **Orçamento: ~1,0 linha de teste por linha de `src/` adicionada.** Passou muito disso, o
   design justifica ou enxuga.
8. **A suíte inteira roda em ~10 min** (com cobertura). Uma spec que a faça passar de ~12 min
   sem motivo explícito reabre a conversa antes do merge.

**Regra de ouro ao enxugar testes:** `uv run pytest --cov` antes e depois, no **mesmo Python**,
comparando por arquivo o conjunto de linhas e branches executados; nada coberto pode deixar de
ser. Teste removido nomeia o que ainda guarda o comportamento.

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
| [`014-file-upload`](014-file-upload/) | LDAP / XPath / SSI injection **in-band** (assinatura de erro do parser + diferencial, forma do `sqli`; `ssi` só prova avaliação) e detecção de upload sem restrição **opt-in** (`--file-upload`): `UploadScanner` sobe marcadores benignos por form de upload, busca de volta e prova execução server-side (CRITICAL), render inline (HIGH), traversal de nome (HIGH) ou aceite de tipo arbitrário (MEDIUM); um probe `PUT` de marcador. `Category.UPLOAD` nova; `HttpClient.request(files=)` novo. Varredura de fronteiras de cobertura ativa (EL/`eval`/NoSQLi/HPP/RFI/cega/smuggling → fora, documentado) | `v0.14` | **done** |
| [`015-web-toolchain-modernization`](015-web-toolchain-modernization/) | moderniza o toolchain do `web/`, sem mudança visual nem no engine: Node 20 (EOL) → 24 (CI, `web/Dockerfile`, `engines`, `@types/node`); Tailwind CSS 3 → 4 (`@tailwindcss/postcss`, `globals.css` CSS-first com os tokens preservados, `tailwind.config.ts` deletado, `tailwind-merge` 3, `tw-animate-css`); Next.js 15 → 16 (`eslint-config-next` 16, `next lint` → `eslint` flat config, Turbopack default). Reparo de CI junto (lockfile do Dependabot quebrado, fallout do vitest 4, e2e que nunca rodou no Linux). Fecha os PRs de version-update #7/#8/#10/#11 | — | **done** |
| [`016-el-injection`](016-el-injection/) | expression-language injection **in-band** (issue #56): `injection.el` (HIGH, CRITICAL quando o type system é alcançável; CWE-917) prova avaliação de SpEL / OGNL / JEXL / MVEL / Unified EL com marcador colado ao produto calculado, em `${}` / `#{}` / `*{}` / `%{}` (OGNL, novo) e na forma de expressão nua; assinaturas de erro de EL; identificação do dialeto por chamada estática pura (`Math.abs`). `injection.ssti` não muda. `eval()` fica fora (decisão da spec) | `v0.16` | **done** |
| [`017-csrf-confirmation`](017-csrf-confirmation/) | confirmação **ativa** do CSRF (issue #54): `csrf.form.token-not-enforced` (MEDIUM, CWE-352) da passada `CsrfScanner`, opt-in `--confirm-csrf` (grava no alvo). Por form `POST` candidato: GET fresco → **controle** (valores default, `Origin` do alvo) → **replays** com `Origin`/`Referer` estrangeiros e o token removido / alterado; só confirma se o controle foi aceito e o replay é equivalente, nunca chuta. Substitui o `csrf.form.no-token` do mesmo form. Roda por último (muda estado). Sem login automático (#52): token preso a sessão que o scan não tem → inconclusivo | `v0.17` | **done** |
| [`018-post-form-crawl`](018-post-form-crawl/) | o crawler passa a **escrever**, opt-in (issue #55): `--submit-post-forms` / `[scan] submit_post_forms`, só Active Mode (grava no alvo). Fase POST dentro de `Crawler.discover()`, depois que a fila de GETs esvazia: submete uma vez cada form candidato (urlencoded ou multipart sem arquivo; mesmo filtro da 017) e cada operação `POST` do `--openapi` (corpo JSON / urlencoded sintetizado pela 013) com valores default + marcador `wvcrawl`, nunca payload. A resposta vira `Page` (`method="POST"`) e realimenta o BFS; quatro passes ignoram páginas de POST. Teto `max_post_submissions` (25). Sem parameter mining, sem login (#52) | `v0.18` | **done** |
| [`019-automated-login`](019-automated-login/) | login automático (issue #52): acha o form de login, envia as credenciais (senha só por variável de ambiente ou prompt), captura a sessão num jar só do host alvo e re-autentica quando ela cai. Só Active Mode, uma tentativa por login, nunca adivinha. Pré-requisito da `020` (issue #53, checks de sessão) | `v0.19` | **done** |
| [`020-session-security`](020-session-security/) | checks de sessão (issue #53): `session.id.weak` (ids fracos ou previsíveis: regras de valor sobre os cookies já vistos + amostragem anônima opt-in `--sample-sessions`), `session.fixation` (o cookie de sessão não muda no login, vem de graça do handshake da `019`, confirmado com 1 GET) e `session.logout.not-invalidated` (opt-in `--test-logout`, só Active, última passada). `Category.SESSION` nova; evidência sem nenhum valor de cookie | `v0.20` | **done** |
| [`021-har-import`](021-har-import/) | import de HAR (issue #146): `--har traffic.har` / `[scan] har` semeia o crawl e os injection points a partir do tráfego que um navegador gravou, para cobrir single-page applications (o crawler não roda JavaScript). Reusa o mecanismo do `--openapi`: o importador devolve `ApiOperation`s (`extra_seeds`, `post_operations`, `enumerate_points`, `source="har"`). Só lê arquivo local, não envia nada por conta própria, ignora hosts fora do escopo, assets estáticos e operações de login/destrutivas, e nunca copia cookie, header ou valor de parâmetro secreto para finding, relatório ou aviso. Sem dependência nova; a API web não aceita o campo | `v0.21` | **draft** |

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
> **`011` a `014` eram a linha de "paridade real" com ZAP/Wapiti** no recorte que a WebVigil
> se propõe a cobrir: as classes de injeção que um revisor notaria faltando (command
> injection, SSTI, CRLF, host header, XXE, LDAP, XPath, SSI, upload) e a largura mínima de
> auth/API. Todas **in-band, sem browser, sem OAST**. **`011`–`014` estão entregues** — a
> `014` fechou a linha (LDAP / XPath / SSI injection + file upload opt-in) e varreu as
> fronteiras de cobertura ativa. Próximo: `v1.0`. Os não-objetivos abaixo continuam valendo
> e viram a seção "Scope and limitations" do README na `v1.0`:
>
> - **Crawl de SPA renderizada em JS** — sem browser headless; escaneie a API direto (a
>   `013` importa OpenAPI) ou alimente URLs de um crawler seu.
> - **Blind / OAST** (blind XSS/SSRF/RCE, XXE OOB) e **HTTP request smuggling** — ver
>   [`docs/notes/why-not-oast.md`](../docs/notes/why-not-oast.md).
> - **OpenAPI em YAML** e **fuzz campo a campo de body JSON** — limites da `013` (JSON só,
>   sem dependência nova; params de query / path / body form-urlencoded são fuzzados), não
>   permanentes.
> - **`eval()` code injection, NoSQLi, HTTP
>   parameter pollution, RFI** — fora da `014` (expression-language injection saiu desta
>   lista na `016`) (deferidas ou sem oráculo in-band confiável);
>   accounting completo em [`docs/active-injection.md`](../docs/active-injection.md#coverage-boundaries).
> - **Base de templates estilo Nuclei**, fuzzing exaustivo, enum de CMS, brute-force de login.
>
> Sequência: `011` → `012` → `013` → `014` (feitas) → `v1.0` (README "Scope and limitations"
> + descrição no GitHub).
