import type { NextConfig } from "next";

/**
 * The dashboard never calls the API cross-origin: every `/api/*` request is proxied
 * server-side to the FastAPI service (spec 002), in development and in production alike.
 * `API_PROXY_TARGET` is read here only — it never reaches the browser bundle (RNF-06).
 * Next bakes `rewrites()` at build time, so in the container the value is a build arg
 * (`docker-compose` sets it); `next dev` reads it live.
 */
const apiProxyTarget = process.env.API_PROXY_TARGET ?? "http://127.0.0.1:8000";

/**
 * `output: "standalone"` is what the Docker image ships (RNF-09). It is opt-in via
 * `NEXT_OUTPUT_STANDALONE` because the trace step symlinks `node_modules`, which needs
 * Developer Mode / admin on Windows; CI (Linux) and the Dockerfile set the flag. The e2e
 * suite and the quality gate use a plain build + `next start`.
 */
const nextConfig: NextConfig = {
  output: process.env.NEXT_OUTPUT_STANDALONE ? "standalone" : undefined,
  // The quality gate runs `pnpm lint` and `pnpm typecheck` explicitly; don't re-lint the
  // whole tree (tests included) during `next build`.
  eslint: { ignoreDuringBuilds: true },
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${apiProxyTarget}/api/:path*` }];
  },
};

export default nextConfig;
