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
});
