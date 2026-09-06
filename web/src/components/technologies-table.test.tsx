import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { TechnologiesTable } from "@/components/technologies-table";
import { makeTechnology } from "@/test/fixtures";
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

describe("TechnologiesTable", () => {
  it("renders vulnerable and clean rows", () => {
    renderWithClient(
      <TechnologiesTable
        items={[
          makeTechnology({ name: "jquery", version: "1.7.1", vulnerable: true }),
          makeTechnology({
            name: "react",
            version: null,
            vulnerable: false,
            advisories: [],
            detection: "uri",
          }),
        ]}
      />,
    );
    expect(screen.getByRole("heading", { name: "Detected technologies" })).toBeInTheDocument();
    expect(screen.getByText("jquery")).toBeInTheDocument();
    expect(screen.getByText("unknown")).toBeInTheDocument();
    expect(screen.getByText(/Vulnerable \(CVE-2011-4969\)/)).toBeInTheDocument();
  });

  it("links a vulnerable row to the matching findings filter", async () => {
    const user = userEvent.setup();
    renderWithClient(<TechnologiesTable items={[makeTechnology()]} />);
    await user.click(screen.getByRole("button", { name: /Vulnerable/ }));
    expect(router.replace).toHaveBeenCalledWith("/scans/7?check_id=deps.js.vulnerable-library");
  });

  it("renders nothing when the inventory is empty", () => {
    const { container } = renderWithClient(<TechnologiesTable items={[]} />);
    expect(container).toBeEmptyDOMElement();
  });
});
