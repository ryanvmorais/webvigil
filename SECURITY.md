# Security Policy

## Authorized use only

WebVigil is a security testing tool. Only use it against systems that you own or for which
you have explicit, written authorization to test. Unauthorized scanning of computer systems
may violate laws such as the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK),
and Art. 154-A of the Brazilian Penal Code, among others.

The authors accept no liability for misuse of this tool.

## Scan modes

- **Safe Mode (`passive`, default)** — WebVigil only observes: it reads response headers,
  TLS configuration, cookies, and page content. It sends no attack payloads and performs no
  state-changing requests. It is designed to be safe to run against production systems.
- **Active Mode (`active`)** — WebVigil sends crafted payloads (injection, fuzzing). It must
  be enabled explicitly with `--mode active --authorized-by "<name / engagement>"` and is
  intended for development and staging environments only. It is always restricted to the
  target host scope.

A "good neighbor" policy is always enforced: bounded concurrency, configurable request delay,
a page-count limit, and a scope guard that blocks requests to out-of-scope hosts.

The optional Web API (`webvigil-web`) and its dashboard (`web/`) can also start Active-Mode
scans. They apply the same gate: a scan with `mode: active` is rejected unless an
`authorized_by` attestation is supplied, and that text is recorded on the scan and shown in
every report.

## Reporting a vulnerability in WebVigil itself

Please report security issues in WebVigil privately via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab) rather than opening a public issue.
We aim to acknowledge reports within 7 days.
