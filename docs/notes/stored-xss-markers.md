# Detecting stored XSS means writing data you can't take back

> Design note for [WebVigil](https://github.com/ryanvmorais/webvigil). Background for
> [spec 008 — stored XSS](../../specs/008-stored-xss/design.md).

Most of what a scanner does is read-only. It fetches pages, inspects headers, sends a
crafted query string and looks at what comes back. Even WebVigil's active injection tests
are, in effect, reads: a `SLEEP(5)` payload changes nothing, an XSS probe changes nothing,
a path-traversal string changes nothing.

Stored cross-site scripting is different. To detect it, you have to **store something** —
submit a payload through a form, then come back and look for it rendered unescaped on
another page. There is no passive way to find stored XSS, and there is no non-invasive
active way either. The act of testing is the act of writing to the target.

And once it is written, you usually can't take it back. The guestbook entry, the profile
field, the support-ticket body — there is often no "delete" button, or deleting needs an
account you don't have, or the content sits in a moderation queue you can't reach. WebVigil
assumes it cannot clean up after itself, because most of the time it can't.

That assumption forced three decisions in the stored-XSS pass shipped in `v0.8`.

## 1. A dedicated opt-in, on top of Active Mode

WebVigil's Active Mode already requires two flags (`--mode active` and `--authorized-by`)
and prints a legal-warning banner. Its documentation already says Active Mode can cause
state changes, because submitting a form can.

But "submits a form that might change state" and "deliberately writes marker rows the target
will keep" are different promises. The stored-XSS pass is gated behind a third flag,
`--stored-xss`, so the user has to say yes to *that specific behaviour* — not infer it from
a general Active Mode warning. Running an Active scan without `--stored-xss` never submits a
stored-XSS marker.

## 2. The marker is inert, and it is signed

The payload is `<wvstored{token}>`. It is a made-up HTML tag: no script, no event handler,
no `javascript:` URL, no attributes. In a browser it does nothing — it is not an XSS payload
in the exploit sense. But if the application failed to escape it, it renders as a DOM
element, and "an element that should not exist now exists in the page" is unambiguous proof
that unescaped user input reached the HTML.

Two more properties matter:

- **It is attributable.** The literal string `wvstored` is in every marker. Anyone auditing
  the target's database months later can search for it and see that WebVigil put it there,
  during a scan, on purpose — not an attacker, not a bug, a test.
- **It is traceable.** `{token}` is a random hex value minted *per injection point*. When
  the re-crawl finds a rendered marker, the token says exactly which parameter on which
  form stored it. Without that, a marker found on `/guestbook/e/7` tells you there is stored
  XSS *somewhere*; with it, the finding names the sink.

## 3. The documentation says it without euphemism

The docs for the feature say: "this pass submits marker payloads the target stores and does
not remove them." Not "may leave test artifacts." Not "is minimally invasive." It writes
data to your application and it does not clean up, and the sentence that says so is short
and direct.

## The mechanic, briefly

The pass has two phases. Phase A enumerates the same injection points the reflected-XSS pass
uses (form fields first, then query parameters) and submits one marker through each. Phase B
is a **depth-1 re-crawl**: it re-fetches every page from the first crawl's frontier, follows
one hop of newly discovered links, and looks for the markers — correlating by token.

It is deliberately not a second full crawl. "Re-fetch what we already saw, plus one hop"
is cheaper and matches how stored XSS actually surfaces: you post to `/guestbook`, and the
entry shows up on `/guestbook` and on a per-entry page linked from it.

One design detail worth calling out: the finding's `location` is the **injection point**,
not the page where the marker rendered. That render page might be `/guestbook/e/7` today and
`/guestbook/e/8` after a few more entries — an unstable URL. The injection point
(`POST /guestbook`, field `body`) is stable, so the finding's fingerprint is stable across
runs, and the render location goes in the evidence instead.

## The broader point

Some detection is inherently invasive, and stored XSS is high-impact enough — it runs for
every user who views the poisoned page, no phishing link required — that skipping it would
be a real hole.

The responsible move is not to skip it. It is to make the invasion **opt-in and explicit**,
to **minimise and sign** what you leave behind, and to **tell the truth about it** in the
documentation. A tool that quietly writes to your database is worse than one that asks first
and leaves its name on everything it touched.
