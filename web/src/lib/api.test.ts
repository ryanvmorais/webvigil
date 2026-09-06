import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";

import { ApiError, api, errorMessage, fieldErrors } from "@/lib/api";
import { server } from "@/test/msw/server";

describe("request", () => {
  it("returns undefined for 204 responses", async () => {
    server.use(http.post("*/api/auth/logout", () => new HttpResponse(null, { status: 204 })));
    await expect(api.logout()).resolves.toBeUndefined();
  });

  it("parses a JSON body on success", async () => {
    server.use(
      http.get("*/api/health", () => HttpResponse.json({ status: "ok", version: "0.2.0" })),
    );
    await expect(api.health()).resolves.toEqual({ status: "ok", version: "0.2.0" });
  });

  it("throws a typed ApiError with a string detail", async () => {
    server.use(
      http.get("*/api/scans/1", () =>
        HttpResponse.json({ detail: "scan not found" }, { status: 404 }),
      ),
    );
    const err = await api.getScan(1).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 404, detail: "scan not found" });
  });

  it("carries the validation array for a 422", async () => {
    server.use(
      http.post("*/api/scans", () =>
        HttpResponse.json(
          { detail: [{ loc: ["body", "target"], msg: "field required", type: "missing" }] },
          { status: 422 },
        ),
      ),
    );
    const err = await api
      .createScan({ target: "", mode: "passive", scope: "host", disabled_checks: [] })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(fieldErrors(err)).toEqual({ target: "field required" });
  });
});

describe("fieldErrors", () => {
  it("is empty for a non-ApiError or a string detail", () => {
    expect(fieldErrors(new Error("boom"))).toEqual({});
    expect(fieldErrors(new ApiError(403, "nope"))).toEqual({});
  });

  it("keeps the first message per field and drops the 'body' prefix", () => {
    const err = new ApiError(422, [
      { loc: ["body", "password"], msg: "too short", type: "value_error" },
      { loc: ["body", "password"], msg: "second", type: "value_error" },
    ]);
    expect(fieldErrors(err)).toEqual({ password: "too short" });
  });
});

describe("errorMessage", () => {
  it("uses the ApiError detail string, then the first validation msg, then the fallback", () => {
    expect(errorMessage(new ApiError(409, "conflict"))).toBe("conflict");
    expect(errorMessage(new ApiError(422, [{ loc: ["body"], msg: "bad", type: "x" }]))).toBe("bad");
    expect(errorMessage({}, "fallback")).toBe("fallback");
  });
});

describe("reportUrl", () => {
  it("builds the format + download query string", () => {
    expect(api.reportUrl(7, "json", true)).toBe("/api/scans/7/report?format=json&download=true");
    expect(api.reportUrl(7, "html", false)).toBe("/api/scans/7/report?format=html&download=false");
  });
});

describe("listScans", () => {
  it("defaults limit to 20 and forwards the status filter", async () => {
    let seen = "";
    server.use(
      http.get("*/api/scans", ({ request }) => {
        seen = new URL(request.url).search;
        return HttpResponse.json({ items: [], next_cursor: null });
      }),
    );
    await api.listScans({ status: "running" });
    expect(seen).toContain("limit=20");
    expect(seen).toContain("status=running");
  });
});
