import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";

import ScansPage from "@/app/(app)/scans/page";
import { server } from "@/test/msw/server";
import { makeScanSummary } from "@/test/fixtures";
import { renderWithClient } from "@/test/render";

const { searchParams } = vi.hoisted(() => ({ searchParams: new URLSearchParams() }));
vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn(), prefetch: vi.fn() }),
  usePathname: () => "/scans",
  useSearchParams: () => searchParams,
}));

describe("ScansPage", () => {
  it("appends the next page when 'Load more' is used", async () => {
    const user = userEvent.setup();
    const page1 = [makeScanSummary({ target: "https://a.test/" })];
    const page2 = [makeScanSummary({ target: "https://b.test/" })];
    server.use(
      http.get("*/api/scans", ({ request }) => {
        const cursor = new URL(request.url).searchParams.get("cursor");
        return cursor
          ? HttpResponse.json({ items: page2, next_cursor: null })
          : HttpResponse.json({ items: page1, next_cursor: "c2" });
      }),
    );

    renderWithClient(<ScansPage />);
    await screen.findByText("https://a.test/");
    expect(screen.queryByText("https://b.test/")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Load more" }));
    await screen.findByText("https://b.test/");
    expect(screen.getByText("https://a.test/")).toBeInTheDocument();
  });

  it("shows an empty state with a call to action", async () => {
    server.use(http.get("*/api/scans", () => HttpResponse.json({ items: [], next_cursor: null })));
    renderWithClient(<ScansPage />);
    await screen.findByText("No scans yet");
    const region = screen.getByText("No scans yet").closest("div") as HTMLElement;
    expect(within(region).getByRole("link", { name: "New scan" })).toBeInTheDocument();
  });

  it("surfaces a load failure with retry", async () => {
    server.use(http.get("*/api/scans", () => HttpResponse.error()));
    renderWithClient(<ScansPage />);
    await screen.findByText("Could not load scans.");
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });
});
