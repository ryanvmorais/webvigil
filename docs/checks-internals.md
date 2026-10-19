# Checks internals

Internal reference for contributors and agents, moved out of `CLAUDE.md` so that file stays small (it is loaded into every Claude Code request). The prose is in Portuguese, as it was in `CLAUDE.md`. For how to write a check, see [writing-checks.md](writing-checks.md).

## Checks and orchestrator steps

**Checks** (`webvigil.checks`) — plugins `PASSIVE`/`ACTIVE`, registrados por decorator +
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
SQLi (error/boolean/time; o boolean semeia um campo vazio com um valor plausível e aceita uma
divisão de classe de status como evidência), path traversal, open redirect. O `Orchestrator` roda um passo
`InjectionScanner` (enumera injection points a partir de query params + `<form>`s
parseados dos corpos já baixados — campos de texto e `<select>`, este testado por último e nunca
alvo do stored XSS —, baseline por ponto, detectores sob um orçamento de
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
marcador, ausente do baseline; na variante Windows o produto tem de vir impresso **depois** do
marcador, como número inteiro) e um estágio time-based (`sleep`/`ping -n`, confirmado
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
`webvigil.checks.csrf` (spec 007): checks passivos — `csrf.form.no-token` marca form
`POST` state-changing sem token anti-CSRF, confiança ponderada pelo `SameSite` do cookie
de sessão (também vê o form `POST` que é só um botão, que o parser agora mantém no inventário), e
`csrf.form.state-change-over-get` (MEDIUM, CWE-352/650) marca form `GET` sem token que troca senha ou
leva verbo destrutivo, sem nunca submetê-lo. Lê `ScanContext.forms` (o crawler agora parseia `<form>`s durante `discover()`
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
boundaries"): `eval()`, NoSQLi, HPP, RFI, DOM XSS, cega/OAST, smuggling e
testes que exigem login stateful ficam de fora.
`injection.el` (HIGH, CRITICAL quando o type system é alcançável; CWE-917) (spec 016):
expression-language injection **in-band** (SpEL / OGNL / JEXL / MVEL / Unified EL), sem flag
e sem config. O detector mora em `detect/el.py` e roda **junto** com o `ssti` num passo único
(`ssti+el`, `_merge_el` no engine) quando os dois checks estão selecionados, para que a mesma
prova nunca vire dois findings nem mande o mesmo payload duas vezes; só `injection.ssti`
selecionado roda o `ssti.detect` de sempre. Prova: marcador colado ao produto de `a*b` em
`${}` / `#{}` / `*{}` / `%{}` (OGNL) e na forma nua `'marker'+(a*b)`; a classificação vem da
evidência, nunca do delimitador (sonda pura `T(java.lang.Math).abs(-n)` /
`@java.lang.Math@abs(-n)` → CRITICAL; um `${}` ambíguo sem evidência de EL continua
`injection.ssti`). `is_exprlike` é estreito de propósito (sem `q` / `message` / `title`).
`_PER_POINT_REQUEST_CAP` 38 → 42. Detalhes em
[`docs/active-injection.md`](docs/active-injection.md#expression-language-injection).
`csrf.form.token-not-enforced` (MEDIUM, CWE-352) (spec 017): confirmação **ativa** do CSRF,
opt-in `--confirm-csrf` / `[injection] csrf_confirm` (default off — **grava no alvo**, até 3
submissões por form, como `--stored-xss` / `--file-upload`). `CsrfScanner`
(`webvigil.checks.csrf.scanner`) é a **última** passada do orquestrador: por form candidato
(POST urlencoded, sem arquivo, fora de auth/busca/destrutivo; teto 20 forms × 5 requests) refaz o
GET da página (token fresco), submete o **controle** (valores default, `Origin` do alvo) e depois
**replays** com `Origin`/`Referer` estrangeiros (`webvigil.invalid`) e o token removido / alterado
(form sem token: um replay). Só **confirma** se o controle foi aceito e o replay é equivalente
(mesma classe de status, mesmo path final, corpo ≥ 95 % similar); rejeitado = refutado; resto =
inconclusivo; nunca chuta. A confirmação **substitui** o `csrf.form.no-token` do mesmo form
(o check passivo lê `observations.csrf_hits`). Confiança = `SameSite` da 007, limitada a MEDIUM
sem `--cookie`. Sem cookie jar por experimento: token preso a sessão que o scan não tem → inconclusivo.
Detalhes em [`docs/authenticated-scanning.md`](docs/authenticated-scanning.md#active-csrf-confirmation----confirm-csrf-opt-in).
Crawler com fase **POST** (spec 018, `v0.18`): opt-in `--submit-post-forms` / `[scan]
submit_post_forms` + `max_post_submissions` (25), **só Active Mode** (default off — **grava no alvo**).
Roda **dentro** de `Crawler.discover()`, depois que a fila de GETs esvazia: submete uma vez cada form
candidato (POST urlencoded ou multipart **sem** arquivo, mesmo filtro `is_candidate` /
`is_destructive_form` da 017) e cada operação `POST` do `--openapi` (corpo JSON / urlencoded que a 013 já
sintetiza; JSON só vem do OpenAPI), com valores default e o marcador `wvcrawl<token>`; nunca payload,
nunca arquivo. Cada resposta vira `Page(method="POST")`, seus links/forms realimentam o mesmo BFS
(`_drain`). `Page.fetched_by_get` faz quatro passes ignorarem páginas de POST (re-crawl do stored-XSS,
pontos GET da injeção, amostra do envelope, pastas do probe). `form_body` (em `crawler/forms.py`) é o
construtor de corpo compartilhado com a 017; `is_candidate` mora em `crawler/safety.py`.
Detalhes em [`docs/authenticated-scanning.md`](docs/authenticated-scanning.md#post-forms----submit-post-forms-opt-in).
Login automático (spec 019, `v0.19`): opt-in `--login-url` + `--username` + `--password-env` /
`[auth.login]`, **só Active Mode** (é um POST real que cria sessão). `webvigil.auth.login.Authenticator`
faz o handshake **pelo `HttpClient`** (scope guard, rate limiter, loop de redirects): GET da página,
escolhe o form com campo de senha, monta o corpo com `form_body` (hidden/CSRF), POST **uma única vez**
(nunca retry, nunca outra credencial), segue a cadeia e **verifica** (marcadores → `check_url` →
heurística; form de login de volta = falha, nada a concluir = "não confirmado" com aviso). Falha =
`LoginFailedError`, exit 4, antes do crawl. A sessão é um `webvigil.http.session.Session`: um
`SessionJar` sobre `httpx.Cookies` (modo handshake aceita todo `Set-Cookie` de todo hop; modo vivo só a
rotação de nomes que já tem; só o host alvo) que o `HttpClient` consulta — `handshake()` / `quiet()`
são `ContextVar`s (o re-login de uma task não vaza pras outras). Queda de sessão = `401`, redirect pro
login a partir de página que não é de login (aprendida uma vez, ADR-6), ou `logged_out_marker`; **`403`
e `5xx` nunca** (payload bloqueado não gasta login); `check_url` confirma antes. Re-login serializado
por número de geração, 1 retry, teto `max_relogins` (3), depois a sessão fica "perdida" com aviso. A
senha **não é campo do `ScanConfig`** (vai como `Credentials`, vinda do env ou de prompt; chave
`password` no TOML é erro); `scrub_result` limpa senha e valores de sessão (4 grafias) dos campos de
texto livre no fim do scan (segredos < 4 chars ficam). `metadata.login` guarda `relogins` /
`session_lost` / `confirmed`, nunca o usuário. Sem login configurado o cliente é byte a byte o de antes
(a regra da 007 de descartar `Set-Cookie` continua). Detalhes em
[`docs/authenticated-scanning.md`](docs/authenticated-scanning.md#automated-login----login-url-opt-in).
Checks de sessão (spec 020, `v0.20`, `Category.SESSION`): `session.id.weak` (PASSIVE),
`session.fixation` e `session.logout.not-invalidated` (ACTIVE). Uma passada `SessionScanner`
(`webvigil.checks.session.scanner`) roda por **último** (depois do `CsrfScanner`, porque o logout
encerra a sessão) e entrega `SessionHit`s sem nenhum valor de cookie (`facts` = números e palavras;
ADR-8) em `observations.session_hits`; os três checks só formatam. Passos: (1) ids que o crawl já viu,
regras de valor em `checks/session/ids.py` (capacidade do alfabeto, não Shannon: 16 hex = 64 bits
passa; numérico, contador, timestamp e repetido são HIGH); (2) `--sample-sessions` /
`[session] sample_ids`, `sample_count` 3..20: N GETs do entry URL em `HttpClient.anonymous()` (sem
cookie nem header estático nem jar), GET-only, vale em qualquer modo, e regras de série (duplicados,
sequência, série de timestamps, baixa variância); (3) fixação: `Authenticator.transition` guarda os
cookies antes/depois do login (de graça, sem 2º login), candidato = cookie de sessão igual nos dois,
confirmado com 1 GET da página de referência (`check_url` ou a de pouso) sem esse cookie; (4)
`--test-logout` / `[session] test_logout` (só Active + login): acha o logout (`logout_url` > 1º link >
1º form POST do crawl, nunca chuta `/logout`), checa que a página de referência anônima parece
deslogada (oráculo), tira o snapshot dos cookies, faz o logout e reenvia o snapshot anônimo;
`Session.close()` impede re-login depois. `anonymous()` é um `ContextVar` como `handshake()`. O jar
passou a recusar cookie `Secure` vindo de resposta `http` (como o navegador). Detalhes em
[`docs/authenticated-scanning.md`](docs/authenticated-scanning.md#session-security-checks).
Import de HAR (spec 021, `v0.21`): `--har PATH` / `[scan] har` + `har_max_operations` (150) semeiam o
crawl e os injection points de SPAs a partir de tráfego gravado no navegador ou num proxy. Segunda
fonte de sementes ao lado do `--openapi`: `webvigil.crawler.har.load_har` (síncrono, arquivo local, não
envia nada) devolve `ApiOperation`s com `source="har"`; o orquestrador faz `merge_operations(openapi,
har)` (a OpenAPI ganha o empate) e as sementes GET usam `ApiOperation.seed_url` (a do HAR leva a query
gravada; a do OpenAPI continua só o path). Só indexa os campos de que precisa: **nunca lê valor de
header, cookie nem corpo de resposta** (o aviso "a gravação parece autenticada" usa só o nome do header),
valor de parâmetro com nome de segredo ou acima de 256 caracteres vira `wv`, corpo JSON entra só como
forma tipada, multipart entra como campos urlencoded (como no `--openapi`). Escopo = `Target.in_scope`
+ o esquema do alvo; a entrada mantém a própria origem. Filtra asset estático, método ≠ GET/POST e
caminho de login/destrutivo; arquivo ruim é `HarError` (exit 4), entrada ruim é contagem no resumo
(`HAR import: N entries read, …`). POST só sai da fase da 018 (Active + `--submit-post-forms`). A Web API
não expõe o campo. Detalhes em [`docs/har-import.md`](docs/har-import.md).
