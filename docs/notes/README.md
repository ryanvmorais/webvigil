# Design notes

Short essays on the reasoning behind specific decisions in WebVigil — the kind of thing
that lives in a spec's ADR section, written up for a reader who wants the *why* without
reading the whole spec. Each note links back to the spec it came from.

| Note | What it's about |
|---|---|
| [The OAST problem: why blind SSRF is the one thing WebVigil won't do](why-not-oast.md) | Why the SSRF checks stop at in-band detection, and why an out-of-band collaborator is not on the roadmap. |
| [False-positive discipline in an active scanner](false-positive-discipline.md) | The baseline-absent / reproduce / executable-context pattern every active detector follows, and what it costs. |
| [Detecting stored XSS means writing data you can't take back](stored-xss-markers.md) | Why the stored-XSS pass is opt-in, why its markers are inert and signed, and why the docs say so plainly. |
| [Keeping a security engine honest with import-linter](engine-boundaries.md) | Why a scan engine needs enforced boundaries, and how a fifteen-line contract test keeps them. |
| [OSV.dev without an API key](osv-without-a-key.md) | Adding an opt-in online advisory source to an offline-first tool — the defaults and failure modes that actually matter. |
