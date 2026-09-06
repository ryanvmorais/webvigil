import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AppShell } from "@/components/app-shell";
import { makeTestClient, withClient } from "@/test/render";

const { pathname } = vi.hoisted(() => ({ pathname: { value: "/scans" } }));
vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn(), prefetch: vi.fn(), refresh: vi.fn() }),
  usePathname: () => pathname.value,
}));

function renderShell() {
  return render(
    <AppShell>
      <p>page body</p>
    </AppShell>,
    { wrapper: withClient(makeTestClient()) },
  );
}

describe("AppShell", () => {
  it("renders the primary nav, a logout control, and a mobile menu trigger", () => {
    pathname.value = "/scans";
    renderShell();

    expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
    for (const label of ["Scans", "Checks", "Settings"]) {
      expect(screen.getAllByRole("link", { name: label }).length).toBeGreaterThan(0);
    }
    expect(screen.getByRole("button", { name: "Open menu" })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /log out/i }).length).toBeGreaterThan(0);
    expect(screen.getByRole("main")).toHaveTextContent("page body");
  });

  it("marks the active route with aria-current", () => {
    pathname.value = "/checks";
    renderShell();
    expect(screen.getByRole("link", { current: "page" })).toHaveTextContent("Checks");
  });
});
