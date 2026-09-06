import { renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { useQueryParams } from "@/hooks/use-query-param";

const { router, searchParams } = vi.hoisted(() => ({
  router: {
    replace: vi.fn(),
    push: vi.fn(),
    prefetch: vi.fn(),
    refresh: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
  },
  searchParams: new URLSearchParams("status=running"),
}));
vi.mock("next/navigation", () => ({
  useRouter: () => router,
  usePathname: () => "/scans",
  useSearchParams: () => searchParams,
}));

describe("useQueryParams.setParams", () => {
  it("adds, replaces, and removes keys while keeping the rest", () => {
    const { result } = renderHook(() => useQueryParams());

    result.current.setParams({ severity: "HIGH" });
    expect(router.replace).toHaveBeenLastCalledWith("/scans?status=running&severity=HIGH");

    result.current.setParams({ status: null });
    expect(router.replace).toHaveBeenLastCalledWith("/scans");
  });
});
