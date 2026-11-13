import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { FindingsFilters } from "@/components/findings-filters";
import { renderWithClient } from "@/test/render";

const { router, searchParams } = vi.hoisted(() => ({
  router: {
    replace: vi.fn(),
    push: vi.fn(),
    prefetch: vi.fn(),
    refresh: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
  },
  searchParams: new URLSearchParams(),
}));
vi.mock("next/navigation", () => ({
  useRouter: () => router,
  usePathname: () => "/scans/7",
  useSearchParams: () => searchParams,
}));
vi.mock("@/components/field-select", () => ({
  FieldSelect: ({ label, value, onValueChange, options }: any) => (
    <select aria-label={label} value={value} onChange={(e) => onValueChange(e.target.value)}>
      {options.map((o: { value: string; label: string }) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  ),
}));
vi.mock("@/hooks/use-findings", () => ({
  useFindingChecks: () => ({
    data: [
      { check_id: "headers.csp", count: 312 },
      { check_id: "tls.version", count: 1 },
    ],
  }),
}));

describe("FindingsFilters", () => {
  afterEach(() => {
    router.replace.mockClear();
    for (const key of [...searchParams.keys()]) searchParams.delete(key);
  });

  it("writes the severity and check-id filters to the URL", async () => {
    const user = userEvent.setup();
    renderWithClient(<FindingsFilters scanId={7} />);

    await user.selectOptions(screen.getByRole("combobox", { name: "Minimum severity" }), "HIGH");
    expect(router.replace).toHaveBeenLastCalledWith("/scans/7?severity=HIGH");

    await user.selectOptions(screen.getByRole("combobox", { name: "Check" }), "tls.version");
    expect(router.replace).toHaveBeenLastCalledWith("/scans/7?check_id=tls.version");
  });

  it("lists only this scan's checks, with their counts", () => {
    renderWithClient(<FindingsFilters scanId={7} />);
    const options = screen
      .getAllByRole("option")
      .map((option) => option.textContent)
      .filter((text) => text?.includes("."));
    expect(options).toEqual(["headers.csp (312)", "tls.version (1)"]);
  });

  it("keeps a check from a shared link that this scan does not have", () => {
    searchParams.set("check_id", "injection.xss");
    renderWithClient(<FindingsFilters scanId={7} />);
    expect(screen.getByRole("option", { name: "injection.xss (0)" })).toBeInTheDocument();
  });

  it("writes the search to the URL once typing pauses", async () => {
    const user = userEvent.setup();
    renderWithClient(<FindingsFilters scanId={7} />);

    await user.type(screen.getByRole("searchbox", { name: "Search findings" }), " admin ");
    expect(router.replace).not.toHaveBeenCalled();
    await waitFor(() => expect(router.replace).toHaveBeenLastCalledWith("/scans/7?q=admin"));
    expect(router.replace).toHaveBeenCalledTimes(1);
  });
});
