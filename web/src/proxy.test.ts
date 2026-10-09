/**
 * @vitest-environment node
 *
 * The proxy that gives every page its Content-Security-Policy — spec 022 RF-01, RF-09, RNF-03.
 *
 * Nothing is mocked: `NextRequest` and `NextResponse` run for real (hence the `node` environment,
 * which has the `Request` and `Headers` classes jsdom lacks), and the policy comes from the real
 * builder. The matcher is read as the regular expression Next compiles from `source`. That the
 * browser enforces the policy is the e2e suite's job.
 */
import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";

import { config, proxy } from "@/proxy";

/**
 * Run the proxy on a page request.
 *
 * @param path - The request path, e.g. `"/login"`.
 * @returns The proxy's response.
 */
function run(path = "/login") {
  return proxy(new NextRequest(`http://localhost:3000${path}`));
}

/**
 * Read the nonce out of a policy.
 *
 * @param policy - A `Content-Security-Policy` header value.
 * @returns The value inside `'nonce-…'`.
 */
function nonceOf(policy: string | null): string {
  const match = policy?.match(/'nonce-([^']+)'/);
  expect(match, "a nonce in the policy").toBeTruthy();
  return (match as RegExpMatchArray)[1];
}

describe("proxy", () => {
  it("sends the policy on the response", () => {
    const policy = run().headers.get("Content-Security-Policy");
    expect(policy).toContain("default-src 'self'");
    expect(policy).toContain("frame-ancestors 'none'");
    expect(nonceOf(policy)).toHaveLength(24);
  });

  it("forwards the same policy to the render, where Next reads the nonce", () => {
    const response = run();
    // Next carries the headers it forwards as `x-middleware-request-*` entries on the response.
    expect(response.headers.get("x-middleware-request-content-security-policy")).toBe(
      response.headers.get("Content-Security-Policy"),
    );
    expect(response.headers.get("x-middleware-override-headers")).toContain(
      "content-security-policy",
    );
  });

  it("keeps the request's own headers when it forwards them", () => {
    const request = new NextRequest("http://localhost:3000/login", {
      headers: { "x-keep-me": "yes" },
    });
    expect(proxy(request).headers.get("x-middleware-request-x-keep-me")).toBe("yes");
  });

  it("draws a new nonce for each request", () => {
    const nonces = new Set(
      Array.from({ length: 20 }, () => nonceOf(run().headers.get("Content-Security-Policy"))),
    );
    expect(nonces.size).toBe(20);
  });

  it("leaves the nonce in the policy alone: no x-nonce header, no other copy", () => {
    const response = run();
    const nonce = nonceOf(response.headers.get("Content-Security-Policy"));
    expect(response.headers.has("x-nonce")).toBe(false);
    expect(response.headers.has("x-middleware-request-x-nonce")).toBe(false);
    for (const [name, value] of response.headers) {
      if (!name.endsWith("content-security-policy")) expect(value, name).not.toContain(nonce);
    }
  });
});

describe("matcher", () => {
  const [rule] = config.matcher;
  // Next anchors the `source` the way path-to-regexp does: the whole path must match.
  const pattern = new RegExp(`^${rule.source}$`);

  it.each(["/", "/login", "/setup", "/scans", "/scans/12", "/scans/new", "/checks", "/settings"])(
    "runs on the page %s",
    (path) => {
      expect(pattern.test(path)).toBe(true);
    },
  );

  it.each([
    "/api/scans",
    "/api/auth/me",
    "/_next/static/chunks/a.js",
    "/_next/image",
    "/favicon.ico",
    "/icon.svg",
  ])("does not run on %s", (path) => {
    expect(pattern.test(path)).toBe(false);
  });

  it("skips prefetch requests, which are not documents", () => {
    expect(rule.missing).toEqual([
      { type: "header", key: "next-router-prefetch" },
      { type: "header", key: "purpose", value: "prefetch" },
    ]);
  });
});
