/**
 * The dashboard's security headers (issue #138, step 1): the list itself and the way
 * `next.config.ts` hands it to Next. The Content-Security-Policy is not in it (spec 022): the proxy
 * sends it, and `csp.test.ts` and `proxy.test.ts` read it.
 *
 * Nothing is mocked: both are plain data and a config function. That the headers really reach the
 * browser is the e2e suite's job (`e2e/security-headers.spec.ts`), not this one's.
 */
import { describe, expect, it } from "vitest";

import nextConfig from "../../next.config";
import { securityHeaders } from "@/lib/security-headers";

describe("securityHeaders", () => {
  it("sends each header once, so a later one cannot silently replace an earlier one", () => {
    const keys = securityHeaders.map((header) => header.key);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("leaves the Content-Security-Policy to the proxy, so a page never gets two (ADR-5)", () => {
    const keys = securityHeaders.map((header) => header.key.toLowerCase());
    expect(keys).not.toContain("content-security-policy");
    expect(keys).not.toContain("content-security-policy-report-only");
  });

  it("forbids framing", () => {
    const byKey = Object.fromEntries(securityHeaders.map((h) => [h.key, h.value]));
    expect(byKey["X-Frame-Options"]).toBe("DENY");
  });

  it("is the four headers of step 1", () => {
    expect(securityHeaders.map((header) => header.key).sort()).toEqual([
      "Permissions-Policy",
      "Referrer-Policy",
      "X-Content-Type-Options",
      "X-Frame-Options",
    ]);
  });

  it("stops MIME sniffing and keeps the path out of cross-origin referrers", () => {
    const byKey = Object.fromEntries(securityHeaders.map((h) => [h.key, h.value]));
    expect(byKey["X-Content-Type-Options"]).toBe("nosniff");
    expect(byKey["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
  });

  it("grants none of the browser features the dashboard does not use", () => {
    const permissions = securityHeaders.find((h) => h.key === "Permissions-Policy")?.value ?? "";
    for (const feature of ["camera", "microphone", "geolocation", "payment", "usb"]) {
      expect(permissions).toContain(`${feature}=()`);
    }
  });
});

describe("next.config headers()", () => {
  it("applies the security headers to every route", async () => {
    const rules = await nextConfig.headers?.();
    expect(rules).toEqual([{ source: "/:path*", headers: securityHeaders }]);
  });
});
