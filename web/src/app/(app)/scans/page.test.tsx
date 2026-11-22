import { screen, waitFor, within } from "@testing-library/react";
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
    expect(screen.queryByText("No scans yet")).not.toBeInTheDocument();
    expect(screen.queryByText("Could not load scans.")).not.toBeInTheDocument();
  });

  it("shows an empty state with a call to action", async () => {
    server.use(http.get("*/api/scans", () => HttpResponse.json({ items: [], next_cursor: null })));
    renderWithClient(<ScansPage />);
    await screen.findByText("No scans yet");
    const region = screen.getByText("No scans yet").closest("div") as HTMLElement;
    expect(within(region).getByRole("link", { name: "New scan" })).toBeInTheDocument();
    expect(screen.getByText("Run your first scan to see it here.")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("filters by the status in the URL, and says the filter, not the list, is empty", async () => {
    const seen = vi.fn();
    searchParams.set("status", "failed");
    server.use(
      http.get("*/api/scans", ({ request }) => {
        seen(new URL(request.url).searchParams.get("status"));
        return HttpResponse.json({ items: [], next_cursor: null });
      }),
    );
    renderWithClient(<ScansPage />);
    await screen.findByText("No scans with this status");
    expect(seen).toHaveBeenCalledWith("failed");
    expect(screen.queryByText("Run your first scan to see it here.")).not.toBeInTheDocument();
    // only the header's link: the empty state offers no second one under a filter
    expect(screen.getAllByRole("link", { name: "New scan" })).toHaveLength(1);
    searchParams.delete("status");
  });

  it("disables 'Load more' while the next page loads", async () => {
    const user = userEvent.setup();
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    server.use(
      http.get("*/api/scans", async ({ request }) => {
        if (!new URL(request.url).searchParams.get("cursor")) {
          return HttpResponse.json({
            items: [makeScanSummary({ target: "https://a.test/" })],
            next_cursor: "c2",
          });
        }
        await gate;
        return HttpResponse.json({ items: [], next_cursor: null });
      }),
    );
    renderWithClient(<ScansPage />);
    await screen.findByText("https://a.test/");
    await user.click(screen.getByRole("button", { name: "Load more" }));
    expect(await screen.findByRole("button", { name: "Loading…" })).toBeDisabled();
    release();
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: /Load more|Loading/ })).not.toBeInTheDocument(),
    );
  });

  it("surfaces a load failure with retry", async () => {
    server.use(http.get("*/api/scans", () => HttpResponse.error()));
    renderWithClient(<ScansPage />);
    await screen.findByText("Could not load scans.");
    expect(screen.queryByText("No scans yet")).not.toBeInTheDocument();

    server.use(
      http.get("*/api/scans", () =>
        HttpResponse.json({
          items: [makeScanSummary({ target: "https://back.test/" })],
          next_cursor: null,
        }),
      ),
    );
    await userEvent.setup().click(screen.getByRole("button", { name: "Retry" }));
    await screen.findByText("https://back.test/");
    expect(screen.queryByText("Could not load scans.")).not.toBeInTheDocument();
  });
});
