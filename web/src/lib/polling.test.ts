import { afterEach, describe, expect, it, vi } from "vitest";

import { DETAIL_POLL_MS, LIST_POLL_MS, detailInterval, listInterval } from "@/lib/polling";

function setVisibility(state: DocumentVisibilityState) {
  vi.spyOn(document, "visibilityState", "get").mockReturnValue(state);
}

afterEach(() => vi.restoreAllMocks());

describe("listInterval", () => {
  it("polls while any row is non-terminal and the tab is visible", () => {
    setVisibility("visible");
    expect(listInterval(["completed", "running"])).toBe(LIST_POLL_MS);
  });

  it("stops when every row is terminal", () => {
    setVisibility("visible");
    expect(listInterval(["completed", "failed", "cancelled"])).toBe(false);
  });

  it("stops when the tab is hidden", () => {
    setVisibility("hidden");
    expect(listInterval(["running"])).toBe(false);
  });
});

describe("detailInterval", () => {
  it("polls a running scan on a visible tab", () => {
    setVisibility("visible");
    expect(detailInterval("running")).toBe(DETAIL_POLL_MS);
  });

  it("stops at a terminal status and for an unknown status", () => {
    setVisibility("visible");
    expect(detailInterval("completed")).toBe(false);
    expect(detailInterval(undefined)).toBe(false);
  });
});
