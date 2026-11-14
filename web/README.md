# WebVigil dashboard

The Next.js dashboard of the WebVigil Web API: a thin client that talks only to the API and
never to the scan engine. What it covers, how it is built and how to run it with the API is in
[docs/web-ui.md](../docs/web-ui.md); the design tokens and the severity scale are in
[docs/web-ui-design.md](../docs/web-ui-design.md).

## Development

The dashboard is managed by `pnpm` (the version is pinned in `packageManager` of
`package.json`). Start the Web API first (`uv run webvigil-web serve`, from the repository
root), then:

```bash
pnpm install
pnpm dev      # http://localhost:3000, proxies /api/* to the API on :8000
pnpm lint && pnpm format:check && pnpm typecheck && pnpm test && pnpm build
pnpm gen:api  # regenerates src/lib/api-types.ts from openapi.json
pnpm test:e2e # Playwright end-to-end run, offline
```
