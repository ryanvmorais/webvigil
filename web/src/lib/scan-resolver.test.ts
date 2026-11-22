/**
 * Guards the lazy loading of the new-scan validation (zod is ~100 KiB gzipped).
 *
 * The bundle test reads the source tree as text: only `scan-resolver.ts` may import zod, and
 * nothing may import `scan-resolver` statically (type-only imports are erased and allowed),
 * otherwise zod lands in the initial bundle of `/scans/new` and in the route prefetch of
 * `/scans`. The resolver tests call it directly; nothing is mocked.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { scanResolver } from "@/lib/scan-resolver";

const SRC = resolve(__dirname, "..");

/** Every non-test `.ts`/`.tsx` file under `src/`, as `[path relative to src, source]` pairs. */
function sourceFiles(dir = SRC): [string, string][] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    if (!/\.tsx?$/.test(entry.name) || /\.test\.tsx?$/.test(entry.name)) return [];
    return [[relative(SRC, path).replaceAll("\\", "/"), readFileSync(path, "utf8")]];
  });
}

/** Whether `source` has a runtime (non `import type`) static import of a module matching `from`. */
function importsStatically(source: string, from: RegExp): boolean {
  return new RegExp(`^import\\s+(?!type\\b)[^;]*?from\\s+["']${from.source}["']`, "m").test(source);
}

describe("zod stays out of the initial bundle", () => {
  const files = sourceFiles().filter(([path]) => path !== "lib/scan-resolver.ts");

  it("is imported only by scan-resolver", () => {
    const offenders = files
      .filter(([, source]) => importsStatically(source, /zod|@hookform\/resolvers\/zod/))
      .map(([path]) => path);
    expect(offenders).toEqual([]);
  });

  it("is reached only through a dynamic import of scan-resolver", () => {
    const offenders = files
      .filter(([, source]) => importsStatically(source, /@\/lib\/scan-resolver/))
      .map(([path]) => path);
    expect(offenders).toEqual([]);
  });
});

describe("scanResolver", () => {
  const valid = {
    target: "https://example.com",
    mode: "passive",
    scope: "host",
    max_pages: "25",
    delay_ms: "0",
    follow_robots: true,
    authorized_by: "",
    disabled_checks: [],
  } as const;

  /** Run the resolver the way react-hook-form does, with no registered fields. */
  const validate = (values: Record<string, unknown>) =>
    scanResolver(values as never, undefined, { fields: {}, shouldUseNativeValidation: false });

  it("coerces numeric strings and hands back the validated values", async () => {
    const result = await validate(valid);
    expect(result.errors).toEqual({});
    expect(result.values).toMatchObject({ max_pages: 25, delay_ms: 0 });
  });

  it("requires an authorization attestation for active scans", async () => {
    const result = await validate({ ...valid, mode: "active" });
    expect(result.errors).toHaveProperty("authorized_by");
  });

  it("refuses the limits above the API's ceilings and accepts the ceilings", async () => {
    const over = await validate({ ...valid, max_pages: "10001", delay_ms: "60001" });
    expect(over.errors).toHaveProperty("max_pages");
    expect(over.errors).toHaveProperty("delay_ms");
    const at = await validate({ ...valid, max_pages: "10000", delay_ms: "60000" });
    expect(at.errors).toEqual({});
  });

  it.each([
    ["max_pages", "0", "a page count of zero"],
    ["max_pages", "1.5", "a fractional page count"],
    ["delay_ms", "-1", "a negative delay"],
    ["delay_ms", "2.5", "a fractional delay"],
  ])("refuses %s = %s (%s)", async (field, value) => {
    const result = await validate({ ...valid, [field]: value });
    expect(Object.keys(result.errors)).toEqual([field]);
  });

  it("accepts the floors: one page, no delay", async () => {
    const result = await validate({ ...valid, max_pages: "1", delay_ms: "0" });
    expect(result.errors).toEqual({});
  });

  it("trims the target, and refuses one that is only spaces", async () => {
    const trimmed = await validate({ ...valid, target: "  https://example.com  " });
    expect(trimmed.values).toMatchObject({ target: "https://example.com" });
    const blank = await validate({ ...valid, target: "   " });
    expect(blank.errors).toHaveProperty("target.message", "Target is required.");
  });

  it("refuses a target over 2048 characters and accepts one of 2048", async () => {
    const base = "https://example.com/";
    const at = await validate({ ...valid, target: base + "a".repeat(2048 - base.length) });
    expect(at.errors).toEqual({});
    const over = await validate({ ...valid, target: base + "a".repeat(2049 - base.length) });
    expect(over.errors).toHaveProperty("target.message", "At most 2048 characters.");
  });

  it.each(["https://example.com", "example.com", "http://localhost:8000/app", "http://app:8000/"])(
    "accepts the target %s",
    async (target) => {
      expect((await validate({ ...valid, target })).errors).toEqual({});
    },
  );

  it.each(["localhost", "not a url", "ftp:/x"])("refuses the target %j", async (target) => {
    expect((await validate({ ...valid, target })).errors).toHaveProperty("target");
  });

  it("accepts both scopes and nothing else", async () => {
    expect((await validate({ ...valid, scope: "subdomains" })).errors).toEqual({});
    expect((await validate({ ...valid, scope: "everything" })).errors).toHaveProperty("scope");
  });

  it("counts an attestation of spaces as none, and caps it at 200 characters", async () => {
    const active = { ...valid, mode: "active" };
    expect((await validate({ ...active, authorized_by: "   " })).errors).toHaveProperty(
      "authorized_by",
    );
    expect((await validate({ ...active, authorized_by: "a".repeat(200) })).errors).toEqual({});
    expect((await validate({ ...active, authorized_by: "a".repeat(201) })).errors).toHaveProperty(
      "authorized_by",
    );
  });
});
