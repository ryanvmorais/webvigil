import { describe, expect, it } from "vitest";

import { absoluteTime, cweUrl, optionsText, relativeTime, reportFilename } from "@/lib/format";

describe("optionsText", () => {
  it("says Defaults when the scan carried no options", () => {
    expect(optionsText({})).toBe("Defaults");
    expect(optionsText(null)).toBe("Defaults");
  });

  it("reads key: value pairs without the underscores", () => {
    expect(optionsText({ max_pages: 12, delay_ms: 1500 })).toBe("max pages: 12, delay ms: 1500");
  });

  it("shows a text value as it is, without JSON quotes", () => {
    expect(optionsText({ scope: "subdomains" })).toBe("scope: subdomains");
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
    expect(absoluteTime(null)).toBe("—");
  });

  it("moves to the larger unit exactly at its size", () => {
    expect(relativeTime("2026-09-06T11:59:00Z", now)).toBe("1 minute ago");
    expect(relativeTime("2026-09-06T11:59:01Z", now)).toBe("59 seconds ago");
  });

  it("says yesterday, not 1 day ago", () => {
    expect(relativeTime("2026-09-05T12:00:00Z", now)).toBe("yesterday");
  });

  it("rounds under a second to seconds", () => {
    expect(relativeTime(new Date(now - 600).toISOString(), now)).toBe("1 second ago");
    expect(relativeTime(new Date(now - 400).toISOString(), now)).toBe("now");
  });
});
