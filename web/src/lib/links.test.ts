import { describe, expect, it } from "vitest";

import { isHttpUrl } from "@/lib/links";

describe("isHttpUrl", () => {
  it.each([
    "https://example.org/ref",
    "http://example.org/ref?a=1&b=2#frag",
    "HTTPS://EXAMPLE.ORG/",
    "https://osv.dev/vulnerability/GHSA-gxr4-xjj5-5px2",
  ])("accepts %s", (value) => {
    expect(isHttpUrl(value)).toBe(true);
  });

  it.each([
    ["javascript:alert(1)", "javascript scheme"],
    ["JaVaScRiPt:alert(1)", "javascript scheme, mixed case"],
    ["data:text/html,<script>alert(1)</script>", "data scheme"],
    ["vbscript:msgbox(1)", "vbscript scheme"],
    ["java\tscript:alert(1)", "tab that a browser drops"],
    ["java\nscript:alert(1)", "newline that a browser drops"],
    [" https://example.org/", "leading space"],
    ["https://example.org/a b", "space inside"],
    ["https://", "no host"],
    ["//example.org/path", "protocol-relative"],
    ["/relative/path", "relative path"],
    ["ftp://example.org/file", "ftp scheme"],
    ["mailto:someone@example.org", "mailto scheme"],
    ["", "empty"],
  ])("rejects %j (%s)", (value) => {
    expect(isHttpUrl(value)).toBe(false);
  });
});
