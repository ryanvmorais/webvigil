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
    expect(screen.getByText("Vulnerable · 1 advisory")).toBeInTheDocument();
  });

  it("keeps the advisory ids out of the badge and in the tooltip", () => {
    renderWithClient(
      <TechnologiesTable
        items={[makeTechnology({ advisories: ["CVE-2011-4969", "CVE-2012-6708", "GHSA-xxxx"] })]}
      />,
    );
    const button = screen.getByRole("button", { name: /Vulnerable/ });
    expect(button).toHaveAttribute("title", "CVE-2011-4969, CVE-2012-6708, GHSA-xxxx");
    expect(button).toHaveTextContent("Vulnerable · 3 advisories");
    expect(button).not.toHaveTextContent("CVE-");
  });

  it("starts the button's name with its visible text and then says what it does", () => {
    renderWithClient(<TechnologiesTable items={[makeTechnology({ advisories: ["a", "b"] })]} />);
    expect(
      screen.getByRole("button", {
        name: "Vulnerable · 2 advisories: show findings for vulnerable libraries",
      }),
    ).toBeInTheDocument();
  });

  it("says just Vulnerable when no advisory id is known", () => {
    renderWithClient(<TechnologiesTable items={[makeTechnology({ advisories: [] })]} />);
    const button = screen.getByRole("button", { name: /Vulnerable/ });
    expect(button).not.toHaveAttribute("title");
    expect(button).toHaveTextContent(/^Vulnerable: show findings/);
  });

  it("scrolls inside a labelled, focusable region", () => {
    renderWithClient(<TechnologiesTable items={[makeTechnology()]} />);
    expect(screen.getByRole("region", { name: "Detected technologies" })).toHaveAttribute(
      "tabindex",
      "0",
    );
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
