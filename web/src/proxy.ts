/**
 * The proxy (Next 16's name for the middleware) that gives every dashboard page its
 * Content-Security-Policy, with a fresh nonce (spec 022, issue #138 step 2).
 *
 * The policy goes in two places: the **request** headers it forwards, where Next reads the
 * `'nonce-…'` back and stamps it on its framework scripts, page bundles and inline scripts, and
 * the **response** the browser receives. It is built here and nowhere else (ADR-5): the four
 * headers that are the same on every route stay in `next.config.ts`.
 *
 * The nonce is never logged and no `x-nonce` header carries it: nothing in the dashboard reads
 * one, and fewer places holding the secret is better (RNF-03, ADR-6). A nonce exists only for a
 * request that is rendered, which is why the root layout opts the tree into dynamic rendering
 * (ADR-3).
 */
import { type NextRequest, NextResponse } from "next/server";

import { buildContentSecurityPolicy, generateNonce } from "@/lib/csp";

/**
 * Attach the policy to the request Next renders and to the response the browser gets.
 *
 * @param request - The incoming page request.
 * @returns The response to continue with, carrying the policy.
 */
export function proxy(request: NextRequest): NextResponse {
  const policy = buildContentSecurityPolicy(generateNonce(), {
    isDev: process.env.NODE_ENV === "development",
  });

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("Content-Security-Policy", policy);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", policy);
  return response;
}

/**
 * Pages only (RF-09, ADR-8). `/api/*` is Next proxying the FastAPI service, whose answers are the
 * API's own; static files and images must stay static; the icon is a file; a prefetch is not a
 * document and would only cost a nonce.
 */
export const config = {
  matcher: [
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico|icon.svg).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
