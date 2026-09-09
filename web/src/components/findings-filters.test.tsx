import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

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
vi.mock("@/hooks/use-checks", () => ({
  useChecks: () => ({ data: [{ id: "headers.csp" }, { id: "tls.version" }] }),
}));

describe("FindingsFilters", () => {
  it("writes the severity and check-id filters to the URL", async () => {
    const user = userEvent.setup();
    renderWithClient(<FindingsFilters />);

    await user.selectOptions(screen.getByRole("combobox", { name: "Minimum severity" }), "HIGH");
    expect(router.replace).toHaveBeenLastCalledWith("/scans/7?severity=HIGH");

    await user.selectOptions(screen.getByRole("combobox", { name: "Check" }), "tls.version");
    expect(router.replace).toHaveBeenLastCalledWith("/scans/7?check_id=tls.version");
  });
});
