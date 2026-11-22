import { act, fireEvent, screen } from "@testing-library/react";
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
    vi.useRealTimers();
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
    const check = screen.getByRole("combobox", { name: "Check" });
    const options = [...check.querySelectorAll("option")].map((option) => option.textContent);
    expect(options).toEqual(["All checks", "headers.csp (312)", "tls.version (1)"]);
  });

  it("keeps a check from a shared link that this scan does not have", () => {
    searchParams.set("check_id", "injection.xss");
    renderWithClient(<FindingsFilters scanId={7} />);
    expect(screen.getByRole("option", { name: "injection.xss (0)" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Check" })).toHaveValue("injection.xss");
  });

  it("adds no zero-count entry for a check this scan does have", () => {
    searchParams.set("check_id", "tls.version");
    renderWithClient(<FindingsFilters scanId={7} />);
    expect(screen.queryByRole("option", { name: "tls.version (0)" })).not.toBeInTheDocument();
    expect(screen.getByRole("option", { name: "tls.version (1)" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Check" })).toHaveValue("tls.version");
  });

  it("starts from the filters already in the URL", () => {
    searchParams.set("severity", "HIGH");
    searchParams.set("q", "admin");
    renderWithClient(<FindingsFilters scanId={7} />);
    expect(screen.getByRole("combobox", { name: "Minimum severity" })).toHaveValue("HIGH");
    expect(screen.getByRole("searchbox", { name: "Search findings" })).toHaveValue("admin");
    expect(screen.getByRole("combobox", { name: "Check" })).toHaveValue("all");
  });

  it("takes a filter out of the URL when it goes back to 'all'", async () => {
    const user = userEvent.setup();
    searchParams.set("severity", "HIGH");
    searchParams.set("check_id", "tls.version");
    renderWithClient(<FindingsFilters scanId={7} />);

    await user.selectOptions(screen.getByRole("combobox", { name: "Minimum severity" }), "all");
    expect(router.replace).toHaveBeenLastCalledWith("/scans/7?check_id=tls.version");
    await user.selectOptions(screen.getByRole("combobox", { name: "Check" }), "all");
    expect(router.replace).toHaveBeenLastCalledWith("/scans/7?severity=HIGH");
  });

  it("stops the search at the API's 200 characters", () => {
    renderWithClient(<FindingsFilters scanId={7} />);
    expect(screen.getByRole("searchbox", { name: "Search findings" })).toHaveAttribute(
      "maxlength",
      "200",
    );
  });

  it("writes the search to the URL once typing pauses", async () => {
    // fake timers: the 300 ms pause is stepped over, not waited out
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    renderWithClient(<FindingsFilters scanId={7} />);
    const box = screen.getByRole("searchbox", { name: "Search findings" });

    fireEvent.change(box, { target: { value: " adm" } });
    await act(() => vi.advanceTimersByTimeAsync(200));
    // a key pressed before the pause ends starts it again
    fireEvent.change(box, { target: { value: " admin " } });
    await act(() => vi.advanceTimersByTimeAsync(299));
    expect(router.replace).not.toHaveBeenCalled();
    await act(() => vi.advanceTimersByTimeAsync(1));
    expect(router.replace).toHaveBeenLastCalledWith("/scans/7?q=admin");
    expect(router.replace).toHaveBeenCalledTimes(1);
  });
});
