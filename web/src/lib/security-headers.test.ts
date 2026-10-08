/**
 * The dashboard's security headers (issue #138, step 1): the list itself and the way
 * `next.config.ts` hands it to Next.
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

  it("forbids framing with the modern directive and its legacy twin", () => {
    const byKey = Object.fromEntries(securityHeaders.map((h) => [h.key, h.value]));
    expect(byKey["Content-Security-Policy"]).toBe("frame-ancestors 'none'");
    expect(byKey["X-Frame-Options"]).toBe("DENY");
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
