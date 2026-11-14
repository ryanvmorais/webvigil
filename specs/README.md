# Specs

WebVigil is built with spec-driven development. Each feature is designed as a spec under
`specs/NNN-name/` before implementation.

## Conventions

- **Numbering:** `NNN` is a sequential three-digit number (`001`, `002`, …), in the order the
  specs are opened. The name is short and in English (`001-foundation`).
- **Files:** each spec has `requirements.md` (what / why), `design.md` (how) and
  `tasks.md` (executable breakdown). Each one has the frontmatter `feature / status / date /
  related / origin`.
- **Phases and gates:** `requirements → design → tasks → implementation`. Each phase ends
  with explicit human approval before moving on.
- **Valid statuses:** `planned` → `draft` → `approved` → `in progress` → `done`.
  (`planned`: a roadmap entry, no spec files yet. `origin: conception` for
  specs written before the implementation; `reverse-engineering` only to document something
  already finished.)
- **Traceability:** requirements are `RF-NN` (functional) and `RNF-NN` (non-functional);
  each task and design decision cites the requirement(s) it satisfies.
- **Language:** specs are in English (project rule).

## Testing a spec

A rule that came out of the test suite audit (issue #101): 1062 tests and hours of integration
runs became 876 tests and ~10 min, without losing a single line or covered branch. Every new
spec follows this in its `design.md` (testing section) and in its `tasks.md`:

1. **Logic is tested in unit tests.** Detector, verdict, payload table, security predicate and
   parser are tested by calling the function with prepared inputs, without a scan.
2. **Integration attaches to a shared scan.** `tests/integration/test_scan_fixture_app.py`
   runs **once per configuration** (the `scan` fixture keeps the result in the session). A new
   scenario reads the result of an existing scan; if it needs a new option, the option goes
   into the scan with everything on (`_full(profile)`), not into a new scan. A new scan only
   when the configuration is incompatible (e.g. `hardened`, or an opt-in that changes what the
   other tests expect).
3. **A fixture route only for a security invariant.** A `tests/fixtures/` test that merely
   repeats a route's response is dispensable: the integration scan already proves the page is
   reached. The ones that stay guard a guarantee (the `ast` evaluator never reaches `eval`, the
   hardened route refuses the replay).
4. **Determinism is tested once.** `test_full_scan_is_deterministic` compares all the
   findings of the full scan; a new spec does not get its own determinism test
   (`scan.fresh(...)` exists for that test and for no other).
5. **A table instead of a copy.** The same assertion over N flags/checks/formats = one
   parametrized test or one driven by the registry. Every new check gets **one row** in
   `tests/unit/test_check_metadata.py` (id, category, mode, severity, CWEs), not a constants
   test of its own.
6. **Security invariants stay tested**, each in at least one test: Passive sends no forged
   request and no `POST`; CSRF / POST crawl passes never send a payload; an opt-in outside
   Active Mode warns and does nothing; configured cookies and headers never reach a report; a
   `POST` page is never re-requested with `GET`.
7. **Budget: ~1.0 test lines per `src/` line added.** Going well past that, the design
   justifies it or trims it.
8. **The whole suite runs in ~10 min** (with coverage). A spec that pushes it past ~12 min
   with no explicit reason reopens the conversation before the merge.

**Golden rule when trimming tests:** `uv run pytest --cov` before and after, on the **same
Python**, comparing per file the set of executed lines and branches; nothing covered may stop
being covered. A removed test names what still guards the behavior.

## Roadmap

| Spec | Scope | Delivery | Status |
|---|---|---|---|
| [`001-foundation`](001-foundation/) | Pure engine, check contract + registry, HTTP layer + scope guard, crawler, `Finding`/`Severity`, Safe/Active mode + authorization gate, reporters (JSON/SARIF/HTML/MD), CLI, v0.1 checks (headers/cookies/TLS/CORS), CI, Dockerfile | CLI `v0.1` | **done** |
| [`002-web-api`](002-web-api/) | FastAPI + SQLite (SQLModel + Alembic) + single-user auth (setup on first run) + async scan execution with a one-at-a-time queue + export endpoints | API `v0.2` | **done** |
| [`003-web-ui`](003-web-ui/) | Next.js dashboard (App Router + Tailwind + shadcn/ui + TanStack Query) consuming the 002 API: setup/login, scan list, new scan, detail with findings, report preview/export, check catalog, settings | Web UI `v0.3` | **done** |
| [`004-deps-fingerprint`](004-deps-fingerprint/) | passive fingerprinting of front-end JS libs + match against a vendored Retire.js database (offline); technology inventory in the result, reports, API and dashboard | `v0.4` | **done** |
| [`005-info-disclosure`](005-info-disclosure/) | stack traces and directory listing (passive) + opt-in probing (`--probe`) of `.git`/`.env`/backups/debug endpoints with a curated catalog and content validation; engine only (no API/UI change) | `v0.5` | **done** |
| [`006-active-injection`](006-active-injection/) | Active Mode: reflected XSS, SQLi (error/boolean/time), path traversal, open redirect; form + injection point discovery; fuzzing step with a budget; vulnerable target app (fixture + compose service) | `v0.6` | **done** |
| [`007-auth-flows`](007-auth-flows/) | authenticated scan by static cookie (`--cookie` / `[auth]`), passive CSRF check (`csrf.form.no-token`, weighted by SameSite), crawl that submits safe `GET` forms + heuristic to avoid logout/destructive links | `v0.7` | **done** |
| [`008-stored-xss`](008-stored-xss/) | stored/persistent XSS: two-phase `StoredXssScanner` pass (injects `<wvstored…>` markers into the `006` injection points, then a 1-hop re-crawl looking for the marker rendered unescaped on another page); Active Mode + opt-in `--stored-xss` (writes data to the target) | `v0.8` | **done** |
| [`009-ssrf`](009-ssrf/) | **in-band** SSRF: an `ssrf` detector in the `006` pass that sends URL payloads and proves the server-side fetch through the target's response — a cloud metadata marker (`injection.ssrf.metadata`, CRITICAL), a `file://` signature / internal service banner / connection error echoing the URL (`injection.ssrf.internal`, HIGH). `is_urllike` prioritizes URL-looking params; no flag, no config. Blind SSRF is out of scope | `v0.9` | **done** |
| [`010-osv-online`](010-osv-online/) | online OSV.dev provider for the `004` dependency fingerprint: an `_osv_lookup` step in the orchestrator (opt-in `--osv-online` / `[deps] osv_online`) that makes one `querybatch` + one `query` per package against `api.osv.dev`, normalizes into the native `Advisory` and merges with the offline Retire.js match (dedup by identifier); failure becomes a warning, no cache | `v0.10` | **done** |
| [`011-rce-injection`](011-rce-injection/) | the in-band server-side injection that the `006` pass was missing: OS command injection (arithmetic echo + time-based, `injection.cmdi.os` CRITICAL) and SSTI (polyglot → error signature → arithmetic evaluation, `injection.ssti` HIGH). Two new detectors in the `InjectionScanner`, `[injection] time_based_cmdi`, `/ping` + `/greet` fixture | `v0.11` | **done** |
| [`012-protocol-injection`](012-protocol-injection/) | in-band request-envelope injection: `injection.crlf` (HIGH — header/body split that `httpx` parses back), `injection.host-header` (MEDIUM/HIGH — sentinel reflected in an absolute URL/`Location`/`<base>`), `injection.xxe` (HIGH, opt-in `--xxe` — content-type flip on POST points), `http.methods.unsafe` (MEDIUM, `Category.HTTP` — XST + advertised dangerous verbs). `crlf`/`xxe` detectors in the `InjectionScanner`; new `EnvelopeScanner` pass for host-header + methods | `v0.12` | **done** |
| [`013-auth-and-api-surface`](013-auth-and-api-surface/) | auth breadth + API surface: header/bearer auth (`--header "Name: Value"` / `[auth] headers`, same secret discipline as the `007` cookie), OpenAPI 3.x / Swagger 2.0 JSON import (`--openapi <path\|url>`) that seeds the crawl (GET operation URLs → `Crawler.extra_seeds`) and the injection pass (query / path / form-urlencoded body fields → `enumerate_points`, `source="openapi"`), and four passive checks: `content.sri.missing`, `content.mixed` (new `Category.CONTENT`), `disclosure.session-id-in-url`, `disclosure.private-ip`. No new dependency; JSON only; no JSON body leaf fuzzing; GET/POST only | `v0.13` | **done** |
| [`014-file-upload`](014-file-upload/) | **in-band** LDAP / XPath / SSI injection (parser error signature + differential, the `sqli` shape; `ssi` only proves evaluation) and **opt-in** unrestricted upload detection (`--file-upload`): `UploadScanner` uploads benign markers through each upload form, fetches them back and proves server-side execution (CRITICAL), inline render (HIGH), filename traversal (HIGH) or arbitrary type acceptance (MEDIUM); a marker `PUT` probe. New `Category.UPLOAD`; new `HttpClient.request(files=)`. Sweep of the active coverage boundaries (EL/`eval`/NoSQLi/HPP/RFI/blind/smuggling → out, documented) | `v0.14` | **done** |
| [`015-web-toolchain-modernization`](015-web-toolchain-modernization/) | modernizes the `web/` toolchain, with no visual change and no engine change: Node 20 (EOL) → 24 (CI, `web/Dockerfile`, `engines`, `@types/node`); Tailwind CSS 3 → 4 (`@tailwindcss/postcss`, CSS-first `globals.css` with the tokens preserved, `tailwind.config.ts` deleted, `tailwind-merge` 3, `tw-animate-css`); Next.js 15 → 16 (`eslint-config-next` 16, `next lint` → `eslint` flat config, Turbopack default). CI repair along with it (broken Dependabot lockfile, vitest 4 fallout, e2e that never ran on Linux). Closes the version-update PRs #7/#8/#10/#11 | — | **done** |
| [`016-el-injection`](016-el-injection/) | **in-band** expression-language injection (issue #56): `injection.el` (HIGH, CRITICAL when the type system is reachable; CWE-917) proves evaluation of SpEL / OGNL / JEXL / MVEL / Unified EL with a marker glued to the computed product, in `${}` / `#{}` / `*{}` / `%{}` (OGNL, new) and in the bare-expression form; EL error signatures; dialect identification through a pure static call (`Math.abs`). `injection.ssti` does not change. `eval()` stays out (spec decision) | `v0.16` | **done** |
| [`017-csrf-confirmation`](017-csrf-confirmation/) | **active** CSRF confirmation (issue #54): `csrf.form.token-not-enforced` (MEDIUM, CWE-352) from the `CsrfScanner` pass, opt-in `--confirm-csrf` (writes to the target). For each candidate `POST` form: fresh GET → **control** (default values, the target's `Origin`) → **replays** with foreign `Origin`/`Referer` and the token removed / altered; it only confirms if the control was accepted and the replay is equivalent, never guesses. Replaces the `csrf.form.no-token` of the same form. Runs last (changes state). No automated login (#52): a token tied to a session the scan does not have → inconclusive | `v0.17` | **done** |
| [`018-post-form-crawl`](018-post-form-crawl/) | the crawler starts to **write**, opt-in (issue #55): `--submit-post-forms` / `[scan] submit_post_forms`, Active Mode only (writes to the target). POST phase inside `Crawler.discover()`, after the GET queue empties: submits each candidate form once (urlencoded or multipart without a file; same filter as the 017) and each `POST` operation of the `--openapi` (JSON / urlencoded body synthesized by the 013) with default values + a `wvcrawl` marker, never a payload. The response becomes a `Page` (`method="POST"`) and feeds the BFS again; four passes ignore POST pages. `max_post_submissions` cap (25). No parameter mining, no login (#52) | `v0.18` | **done** |
| [`019-automated-login`](019-automated-login/) | automated login (issue #52): finds the login form, sends the credentials (password only through an environment variable or prompt), captures the session in a jar for the target host only and re-authenticates when it drops. Active Mode only, one attempt per login, never guesses. Prerequisite of the `020` (issue #53, session checks) | `v0.19` | **done** |
| [`020-session-security`](020-session-security/) | session checks (issue #53): `session.id.weak` (weak or predictable ids: value rules over the cookies already seen + opt-in anonymous sampling `--sample-sessions`), `session.fixation` (the session cookie does not change on login, comes for free from the `019` handshake, confirmed with 1 GET) and `session.logout.not-invalidated` (opt-in `--test-logout`, Active only, last pass). New `Category.SESSION`; evidence with no cookie value at all | `v0.20` | **done** |
| [`021-har-import`](021-har-import/) | HAR import (issue #146): `--har traffic.har` / `[scan] har` seeds the crawl and the injection points from the traffic a browser recorded, to cover single-page applications (the crawler does not run JavaScript). Reuses the `--openapi` mechanism: the importer returns `ApiOperation`s (`extra_seeds`, `post_operations`, `enumerate_points`, `source="har"`). Only reads a local file, sends nothing on its own, ignores out-of-scope hosts, static assets and login/destructive operations, and never copies a cookie, header or secret parameter value into a finding, report or warning. No new dependency; the web API does not accept the field | `v0.21` | **done** |
| [`022-dashboard-csp`](022-dashboard-csp/) | dashboard Content-Security-Policy (issue #138, step 2): the Next 16 `proxy.ts` generates a per-request nonce and the policy (`script-src 'self' 'nonce-…' 'strict-dynamic'`, `default-src 'self'`, `frame-src blob:` for the report preview, no `upgrade-insecure-requests`); every page now renders per request; `style-src` keeps `'unsafe-inline'` (the toast injects a `<style>` without a nonce). Pure function tested + an e2e that fails on any violation. `web/` only; no engine or API change | `v0.22` | **done** |

> The 002 was split: `002-web-api` (backend) and `003-web-ui` (Next.js). The original
> roadmap treated the two as a single spec; the others were renumbered.
>
> **`008` to `010` were the three accumulated technical debts**, attackable in any order —
> **all delivered**. `008-stored-xss` (`v0.8`): a two-phase pass with a 1-hop re-crawl looking
> for the marker it wrote itself (opt-in `--stored-xss`). `010-osv-online`
> (`v0.10`): opt-in online OSV.dev provider (`--osv-online`), a follow-up to the `004`.
> `009-ssrf` (`v0.9`): **in-band** SSRF — a deliberate cut, no OAST collector, no cost,
> no infrastructure.
>
> **Blind SSRF is not on the roadmap.** Detecting it requires an out-of-band (OAST) collector —
> a server the scanner hosts, with a public domain and DNS/HTTP ports — which crosses the
> principle "the engine only talks to the target" and the decision to distribute the tool only
> through the repository, with no hosted service. Whoever needs to cover the blind case pairs
> WebVigil with an external collaborator of their own (Burp Collaborator, interactsh).
>
> **Automated login and session tests** (fixation, invalidation on logout, weak id)
> were in the original `007` line, which delivered static cookie + passive CSRF + `GET` form
> crawl. They came later, each requiring the stateful login flow or Active Mode: automated
> login in the `019` and the session tests in the `020`. **Header/bearer auth came in the
> `013`** (it does not need a stateful login).
>
> **`011` to `014` were the "real parity" line** with ZAP/Wapiti within the cut WebVigil sets
> out to cover: the injection classes a reviewer would notice missing (command
> injection, SSTI, CRLF, host header, XXE, LDAP, XPath, SSI, upload) and the minimum breadth of
> auth/API. All **in-band, no browser, no OAST**. **`011`-`014` are delivered** — the
> `014` closed the line (LDAP / XPath / SSI injection + opt-in file upload) and swept the
> active coverage boundaries. The non-goals below still hold and have been in the
> "Scope and limitations" section of the README since `v1.0`:
>
> - **Crawling JS-rendered SPAs** — no headless browser; scan the API directly (the
>   `013` imports OpenAPI), feed a HAR recorded in the browser (the `021`, `--har`) or URLs from
>   a crawler of your own.
> - **Blind / OAST** (blind XSS/SSRF/RCE, OOB XXE) and **HTTP request smuggling** — see
>   [`docs/notes/why-not-oast.md`](../docs/notes/why-not-oast.md).
> - **OpenAPI in YAML** and **field-by-field JSON body fuzzing** — limits of the `013` (JSON
>   only, no new dependency; query / path / form-urlencoded body params are fuzzed).
> - **`eval()` code injection, NoSQLi, HTTP
>   parameter pollution, RFI** — outside the `014` (expression-language injection left this
>   list in the `016`) (no reliable in-band oracle);
>   full accounting in [`docs/active-injection.md`](../docs/active-injection.md#coverage-boundaries).
> - **Nuclei-style template base**, exhaustive fuzzing, CMS enumeration, login brute-force.
>
> Sequence: `011` → `012` → `013` → `014` → `v1.0` (README "Scope and limitations"
> + GitHub description), all delivered.
