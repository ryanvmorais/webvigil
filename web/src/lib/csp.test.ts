/**
 * The Content-Security-Policy builder and the nonce generator — spec 022 RF-01 to RF-04, RNF-04.
 *
 * Nothing is mocked: both functions are pure (the nonce reads `crypto`, which Node provides). That
 * the policy reaches the browser and holds there is the e2e suite's job
 * (`e2e/security-headers.spec.ts`, `e2e/smoke.spec.ts`).
 */
import { describe, expect, it } from "vitest";

import { buildContentSecurityPolicy, generateNonce } from "@/lib/csp";

const NONCE = "Zm9vYmFyYmF6cXV4MTIzNA==";

/**
 * Split a policy into its directives.
 *
 * @param policy - A `Content-Security-Policy` header value.
 * @returns Directive name to its value list, in order of appearance.
 */
function parse(policy: string): Map<string, string[]> {
  const directives = new Map<string, string[]>();
  for (const part of policy.split("; ")) {
    const [name, ...values] = part.split(" ");
    expect(directives.has(name), `${name} appears once`).toBe(false);
    directives.set(name, values);
  }
  return directives;
}

describe("buildContentSecurityPolicy", () => {
  const production = parse(buildContentSecurityPolicy(NONCE, { isDev: false }));

  it("lists every directive once, with the value the design gives it", () => {
    expect(Object.fromEntries(production)).toEqual({
      "default-src": ["'self'"],
      "script-src": ["'self'", `'nonce-${NONCE}'`, "'strict-dynamic'"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "img-src": ["'self'", "data:", "blob:"],
      "font-src": ["'self'"],
      "connect-src": ["'self'"],
      "frame-src": ["blob:"],
      "object-src": ["'none'"],
      "base-uri": ["'self'"],
      "form-action": ["'self'"],
      "frame-ancestors": ["'none'"],
    });
  });

  it("puts the nonce in script-src only, and keeps scripts off 'unsafe-inline'", () => {
    const policy = buildContentSecurityPolicy(NONCE, { isDev: false });
    expect(policy.split(NONCE)).toHaveLength(2);
    expect(production.get("script-src")).not.toContain("'unsafe-inline'");
    expect(production.get("script-src")).not.toContain("'unsafe-eval'");
  });

  it("adds eval and the HMR socket in development, and only there", () => {
    const dev = parse(buildContentSecurityPolicy(NONCE, { isDev: true }));
    expect(dev.get("script-src")).toContain("'unsafe-eval'");
    expect(dev.get("connect-src")).toEqual(["'self'", "ws:", "wss:"]);

    const prod = buildContentSecurityPolicy(NONCE, { isDev: false });
    for (const token of ["'unsafe-eval'", "ws:", "wss:"]) {
      expect(prod).not.toContain(token);
    }
  });

  it("does not upgrade the dashboard's own http requests", () => {
    for (const isDev of [false, true]) {
      expect(buildContentSecurityPolicy(NONCE, { isDev })).not.toContain(
        "upgrade-insecure-requests",
      );
    }
  });

  it("gives the same string for the same inputs", () => {
    expect(buildContentSecurityPolicy(NONCE, { isDev: false })).toBe(
      buildContentSecurityPolicy(NONCE, { isDev: false }),
    );
  });
});

describe("generateNonce", () => {
  it("is 128 bits of base64", () => {
    const nonce = generateNonce();
    expect(nonce).toMatch(/^[A-Za-z0-9+/]{22}==$/);
    expect(atob(nonce)).toHaveLength(16);
  });

  it("does not repeat", () => {
    const nonces = new Set(Array.from({ length: 100 }, generateNonce));
    expect(nonces.size).toBe(100);
  });
});
