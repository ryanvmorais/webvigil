import { describe, expect, it } from "vitest";

import { cweUrl, relativeTime, reportFilename } from "@/lib/format";

describe("cweUrl", () => {
  it("links to the MITRE definition", () => {
    expect(cweUrl(79)).toBe("https://cwe.mitre.org/data/definitions/79.html");
  });
});

describe("reportFilename", () => {
  it("is webvigil-{id}.{ext}", () => {
    expect(reportFilename(12, "sarif")).toBe("webvigil-12.sarif");
  });
});

describe("relativeTime", () => {
  const now = Date.parse("2026-09-06T12:00:00Z");

  it("picks the largest fitting unit in the past", () => {
    expect(relativeTime("2026-09-06T11:58:00Z", now)).toBe("2 minutes ago");
    expect(relativeTime("2026-09-04T12:00:00Z", now)).toBe("2 days ago");
  });

  it("handles a null timestamp", () => {
    expect(relativeTime(null, now)).toBe("—");
  });
});
