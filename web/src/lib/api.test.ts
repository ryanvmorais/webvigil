import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";

import { ApiError, SCAN_STATUSES, api, errorMessage, fieldErrors } from "@/lib/api";
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
    // `toContain("limit=20")` would pass for 200 too
    expect(new URLSearchParams(seen).get("limit")).toBe("20");
    expect(new URLSearchParams(seen).get("status")).toBe("running");
  });
});

describe("api calls", () => {
  type Seen = { method: string; path: string; type: string | null; body: string };

  /** Answer every route with 200 `{}` and record what each request looked like. */
  function record(): Seen[] {
    const seen: Seen[] = [];
    server.use(
      http.all("*/api/*", async ({ request }) => {
        seen.push({
          method: request.method,
          path: new URL(request.url).pathname,
          type: request.headers.get("content-type"),
          body: await request.text(),
        });
        return HttpResponse.json({});
      }),
    );
    return seen;
  }

  it.each([
    ["setup", () => api.setup({ username: "a", password: "b" }), "POST", "/api/setup", true],
    ["login", () => api.login({ username: "a", password: "b" }), "POST", "/api/auth/login", true],
    ["logout", () => api.logout(), "POST", "/api/auth/logout", false],
    ["me", () => api.me(), "GET", "/api/auth/me", false],
    [
      "changePassword",
      () => api.changePassword({ current_password: "a", new_password: "b" }),
      "POST",
      "/api/auth/password",
      true,
    ],
    ["getScan", () => api.getScan(3), "GET", "/api/scans/3", false],
    ["cancelScan", () => api.cancelScan(3), "POST", "/api/scans/3/cancel", false],
    ["deleteScan", () => api.deleteScan(3), "DELETE", "/api/scans/3", false],
    ["findings", () => api.findings(3), "GET", "/api/scans/3/findings", false],
    ["findingChecks", () => api.findingChecks(3), "GET", "/api/scans/3/findings/checks", false],
  ] as const)("%s sends %s %s", async (_name, call, method, path, hasBody) => {
    const seen = record();
    await call();
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ method, path });
    // a JSON body is declared as one; a request without a body declares nothing
    expect(seen[0].type).toBe(hasBody ? "application/json" : null);
    if (hasBody) expect(JSON.parse(seen[0].body)).toBeTypeOf("object");
    else expect(seen[0].body).toBe("");
  });

  it("sends the body it was given", async () => {
    const seen = record();
    await api.login({ username: "ana", password: "secret" });
    expect(JSON.parse(seen[0].body)).toEqual({ username: "ana", password: "secret" });
  });

  it("sends the session cookie with every request, the report included", async () => {
    record();
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    await api.me();
    await api.reportBlob(3);
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    for (const [, init] of fetchSpy.mock.calls) expect(init?.credentials).toBe("include");
  });

  it("leaves empty and missing filters out of the query string", async () => {
    let search = "?unset";
    server.use(
      http.get("*/api/scans/3/findings", ({ request }) => {
        search = new URL(request.url).search;
        return HttpResponse.json({ items: [], next_cursor: null, total: 0 });
      }),
    );
    await api.findings(3, { q: "", severity: undefined, check_id: "headers.csp" });
    expect(search).toBe("?check_id=headers.csp");
  });
});

describe("errors", () => {
  it("uses the string detail as the message, and a generic one for a validation list", () => {
    expect(new ApiError(404, "scan not found").message).toBe("scan not found");
    expect(new ApiError(422, [{ loc: ["body", "x"], msg: "bad", type: "t" }]).message).toBe(
      "validation error",
    );
  });

  it("falls back to the status text when the error has no JSON detail", async () => {
    server.use(
      http.get("*/api/health", () => new HttpResponse("upstream down", { status: 502 })),
      http.get("*/api/scans/3/report", () => new HttpResponse("<html>", { status: 503 })),
    );
    await expect(api.health()).rejects.toMatchObject({ status: 502, detail: "Bad Gateway" });
    await expect(api.reportBlob(3)).rejects.toMatchObject({
      status: 503,
      detail: "Service Unavailable",
    });
  });

  it("turns a refused report into an ApiError with its detail, not a blob", async () => {
    server.use(
      http.get("*/api/scans/3/report", () =>
        HttpResponse.json({ detail: "scan is still running" }, { status: 409 }),
      ),
    );
    const err = await api.reportBlob(3).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 409, detail: "scan is still running" });
  });

  it("hands back the report as a blob when it loads", async () => {
    server.use(
      http.get(
        "*/api/scans/3/report",
        () => new HttpResponse("<h1>Report</h1>", { headers: { "content-type": "text/html" } }),
      ),
    );
    expect(await (await api.reportBlob(3)).text()).toBe("<h1>Report</h1>");
  });

  it("files an error with no field name under no field", () => {
    const err = new ApiError(422, [{ loc: ["body"], msg: "invalid JSON", type: "json_invalid" }]);
    expect(fieldErrors(err)).toEqual({});
  });

  it("uses the message of any other Error", () => {
    expect(errorMessage(new TypeError("fetch failed"), "fallback")).toBe("fetch failed");
  });
});

describe("SCAN_STATUSES", () => {
  it("is the API's ScanStatus enum, in order (web/openapi.json)", () => {
    const spec = JSON.parse(readFileSync(resolve(__dirname, "../../openapi.json"), "utf8"));
    expect(SCAN_STATUSES).toEqual(spec.components.schemas.ScanStatus.enum);
  });
});
