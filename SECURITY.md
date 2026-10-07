# Security Policy

## Supported Versions

Only the latest release receives security fixes: the newest `1.x` once `1.0.0` is published,
and `main` until then.

| Version | Supported |
|---|---|
| latest `1.x` release | yes |
| older releases | no |

## Reporting a Vulnerability

Please report security issues in WebVigil itself **privately**, through GitHub Security
Advisories: open the repository's **Security** tab and choose **Report a vulnerability**.
Do not open a public issue or pull request for it.

Include what is needed to reproduce it: the WebVigil version (`webvigil version`) or commit,
the command or configuration, what you expected and what happened, and the impact you see.
A proof of concept against a system you own or a local test target is ideal.

We aim to **acknowledge a report within 7 days** and to send a first assessment within 14.

## Disclosure Policy

We follow coordinated disclosure. A fix is prepared privately, released, and then the advisory
is published; the target is **90 days** from the report at most, sooner when a fix is ready.
We credit the reporter in the advisory unless asked not to.

## Authorized use only

WebVigil is a security testing tool. Only use it against systems that you own or for which
you have explicit, written authorization to test. Unauthorized scanning of computer systems
may violate laws such as the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK),
and Art. 154-A of the Brazilian Penal Code, among others.

The authors accept no liability for misuse of this tool.

## Scope

**Report here** (a vulnerability in WebVigil itself): anything that lets the tool be turned
against its user or a third party, or that breaks one of its safety guarantees. For example:

- a request sent to a host outside the scan scope (a scope-guard bypass);
- Active Mode running without `--authorized-by`, or a Passive scan sending a crafted request;
- a cookie, header, password or session value reaching a report, a log line or the scan
  metadata;
- an authentication or authorization bypass, injection, SSRF or path traversal in the Web API
  or the dashboard;
- unsafe handling of an untrusted input the tool reads (a crawled page, an OpenAPI document,
  a saved scan file, a configuration file);
- a dependency vulnerability that is exploitable through WebVigil.

**Not a vulnerability in WebVigil**: a finding the tool produces about a target (that is for
the target's owner, not for this project), and a false positive or a missed detection (open a
regular bug report instead). Please do not scan systems you are not authorized to test while
investigating.

## Scan modes

- **Safe Mode (`passive`, default)** — WebVigil only observes: it reads response headers,
  TLS configuration, cookies, and page content. It sends no attack payloads and performs no
  state-changing requests. It is designed to be safe to run against production systems.
- **Active Mode (`active`)** — WebVigil sends crafted payloads (injection, fuzzing). It must
  be enabled explicitly with `--mode active --authorized-by "<name / engagement>"` and is
  intended for development and staging environments only. It is always restricted to the
  target host scope. Some opt-in switches write to the target or make a real login request
  (`--stored-xss`, `--file-upload`, `--confirm-csrf`, `--submit-post-forms`, `--login-url`,
  `--test-logout`); each is off by default and documented in the README.

A "good neighbor" policy is always enforced: bounded concurrency, configurable request delay,
a page-count limit, and a scope guard that blocks requests to out-of-scope hosts.

The optional Web API (`webvigil-web`) and its dashboard (`web/`) can also start Active-Mode
scans. They apply the same gate: a scan with `mode: active` is rejected unless an
`authorized_by` attestation is supplied, and that text is recorded on the scan and shown in
every report.
