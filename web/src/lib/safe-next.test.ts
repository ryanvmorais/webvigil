import { describe, expect, it } from "vitest";

import { safeNext } from "@/lib/safe-next";

describe("safeNext", () => {
  it.each(["/scans", "/scans/9", "/scans/9?tab=findings", "/scans/9#top", "/a//b", "/%2F"])(
    "keeps the in-app path %s",
    (path) => {
      expect(safeNext(path)).toBe(path);
    },
  );

  it.each([
    ["//example.com", "protocol-relative"],
    ["///example.com", "protocol-relative with extra slashes"],
    ["/\\example.com", "backslash, which browsers turn into //"],
    ["/\texample.com", "tab inside the path"],
    ["/\t/example.com", "tab that makes it // once stripped"],
    ["/\n/example.com", "newline that makes it // once stripped"],
    ["https://example.com", "absolute URL"],
    ["javascript:alert(1)", "javascript: URL"],
    ["example.com", "no leading slash"],
    ["", "empty"],
  ])("falls back for %j (%s)", (value) => {
    expect(safeNext(value)).toBe("/scans");
  });

  it("falls back when the parameter is absent", () => {
    expect(safeNext(null)).toBe("/scans");
  });

  it("uses the fallback it is given", () => {
    expect(safeNext("//example.com", "/")).toBe("/");
  });
});
