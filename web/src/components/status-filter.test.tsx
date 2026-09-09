import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { StatusFilter } from "@/components/status-filter";

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
  usePathname: () => "/scans",
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

describe("StatusFilter", () => {
  it("writes the chosen status into the URL and clears it for 'all'", async () => {
    const user = userEvent.setup();
    const { unmount } = render(<StatusFilter />);
    await user.selectOptions(screen.getByRole("combobox", { name: "Filter by status" }), "running");
    expect(router.replace).toHaveBeenCalledWith("/scans?status=running");
    unmount();

    searchParams.set("status", "running");
    router.replace.mockClear();
    render(<StatusFilter />);
    await user.selectOptions(screen.getByRole("combobox", { name: "Filter by status" }), "all");
    expect(router.replace).toHaveBeenCalledWith("/scans");
    searchParams.delete("status");
  });
});
