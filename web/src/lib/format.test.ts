import { describe, expect, it } from "vitest";

import { cweUrl, optionsText, relativeTime, reportFilename } from "@/lib/format";

describe("optionsText", () => {
  it("says Defaults when the scan carried no options", () => {
    expect(optionsText({})).toBe("Defaults");
    expect(optionsText(null)).toBe("Defaults");
  });

  it("reads key: value pairs without the underscores", () => {
    expect(optionsText({ max_pages: 12, delay_ms: 1500 })).toBe("max pages: 12, delay ms: 1500");
  });

  it("keeps a nested value as JSON instead of [object Object]", () => {
    expect(optionsText({ disabled_checks: ["a.b"] })).toBe('disabled checks: ["a.b"]');
  });
});

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
