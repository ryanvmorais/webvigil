import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { toast } from "sonner";
import { describe, expect, it, vi } from "vitest";

import ScanDetailPage from "@/app/(app)/scans/[id]/page";
import { keys } from "@/lib/query-keys";
import { makeFinding, makeScanOut, makeTechnology } from "@/test/fixtures";
import { server } from "@/test/msw/server";
import { renderWithClient } from "@/test/render";

const { router, params, searchParams } = vi.hoisted(() => ({
  router: {
    replace: vi.fn(),
    push: vi.fn(),
    prefetch: vi.fn(),
    refresh: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
  },
  params: { value: { id: "7" } as Record<string, string> },
  searchParams: { value: new URLSearchParams() },
}));
vi.mock("next/navigation", () => ({
  useRouter: () => router,
  useParams: () => params.value,
  usePathname: () => "/scans/7",
  useSearchParams: () => searchParams.value,
}));
vi.mock("@/components/confirm-button", () => ({
  ConfirmButton: ({ label, onConfirm, disabled }: any) => (
    <button type="button" onClick={onConfirm} disabled={disabled}>
      {label}
    </button>
  ),
}));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));
vi.mock("@/components/report-menu", () => ({ ReportMenu: () => null }));
// the preview button stands in for the real one: only whether the page enables it is checked here
vi.mock("@/components/report-preview", () => ({
  ReportPreview: ({ disabled }: { disabled: boolean }) => (
    <button type="button" disabled={disabled}>
      Preview report
    </button>
  ),
}));

function mockScan(scan: Record<string, unknown>, findings: unknown[] = []) {
  server.use(
    http.get("*/api/scans/7", () => HttpResponse.json(scan)),
    http.get("*/api/scans/7/findings", () =>
      HttpResponse.json({ items: findings, next_cursor: null, total: findings.length }),
    ),
    http.get("*/api/scans/7/findings/checks", () => HttpResponse.json([])),
  );
}

describe("ScanDetailPage", () => {
  it("shows the header details", async () => {
    mockScan(
      makeScanOut({ id: 7, target: "https://acme.test/", status: "completed", pages_scanned: 4 }),
    );
    renderWithClient(<ScanDetailPage />);
    await screen.findByRole("heading", { name: "https://acme.test/" });
    expect(screen.getByText("4")).toBeInTheDocument();
    expect(screen.getByText("Completed")).toBeInTheDocument();
    // a passive scan names no attester, and a completed one has no error row
    expect(screen.queryByText("Authorized by")).not.toBeInTheDocument();
    expect(screen.queryByText("Error")).not.toBeInTheDocument();
  });

  it.each([
    ["completed", true],
    ["interrupted", true],
    ["running", false],
    ["failed", false],
  ])("enables the report preview of a %s scan: %s", async (status, enabled) => {
    mockScan(makeScanOut({ id: 7, status }));
    renderWithClient(<ScanDetailPage />);
    const preview = await screen.findByRole("button", { name: "Preview report" });
    if (enabled) expect(preview).toBeEnabled();
    else expect(preview).toBeDisabled();
  });

  it("renders a not-found state for a missing scan", async () => {
    server.use(
      http.get("*/api/scans/7", () =>
        HttpResponse.json({ detail: "scan not found" }, { status: 404 }),
      ),
      http.get("*/api/scans/7/findings", () =>
        HttpResponse.json({ items: [], next_cursor: null, total: 0 }),
      ),
      http.get("*/api/scans/7/findings/checks", () => HttpResponse.json([])),
    );
    renderWithClient(<ScanDetailPage />);
    // the placeholder is the whole page, so its title is the page's h1 (axe page-has-heading-one)
    await screen.findByRole("heading", { level: 1, name: "Scan not found" });
    await waitFor(() => expect(document.title).toBe("Scan not found | WebVigil"));
  });

  it("lists findings in the order the API returns them", async () => {
    mockScan(makeScanOut({ id: 7, status: "completed" }), [
      makeFinding({ title: "Low first", severity: "LOW", fingerprint: "a" }),
      makeFinding({ title: "High second", severity: "HIGH", fingerprint: "b" }),
    ]);
    renderWithClient(<ScanDetailPage />);
    const rows = await screen.findAllByRole("row");
    const body = rows.slice(1).map((r) => r.textContent);
    expect(body[0]).toContain("Low first");
    expect(body[1]).toContain("High second");
    expect(screen.queryByText("Could not load findings.")).not.toBeInTheDocument();
    expect(screen.queryByText(/produced no findings|match this filter/)).not.toBeInTheDocument();
  });

  it("appends the next page of findings when 'Load more' is used", async () => {
    mockScan(makeScanOut({ id: 7, status: "completed" }));
    server.use(
      http.get("*/api/scans/7/findings", ({ request }) =>
        new URL(request.url).searchParams.get("cursor") === "c2"
          ? HttpResponse.json({
              items: [makeFinding({ title: "Second page", fingerprint: "b" })],
              next_cursor: null,
              total: 2,
            })
          : HttpResponse.json({
              items: [makeFinding({ title: "First page", fingerprint: "a" })],
              next_cursor: "c2",
              total: 2,
            }),
      ),
    );
    const user = userEvent.setup();
    renderWithClient(<ScanDetailPage />);
    await screen.findByText("First page");
    expect(screen.getByText("1 of 2 findings shown")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Load more" }));
    await screen.findByText("Second page");
    expect(screen.getByText("First page")).toBeInTheDocument();
    expect(screen.getByText("All 2 findings shown")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Load more" })).not.toBeInTheDocument();
  });

  it("sends the search from the URL to the API", async () => {
    const seen = vi.fn();
    searchParams.value = new URLSearchParams("q=admin");
    mockScan(makeScanOut({ id: 7, status: "completed" }));
    server.use(
      http.get("*/api/scans/7/findings", ({ request }) => {
        seen(new URL(request.url).searchParams.get("q"));
        return HttpResponse.json({ items: [], next_cursor: null, total: 0 });
      }),
    );
    renderWithClient(<ScanDetailPage />);
    await screen.findByText("No findings match this filter");
    expect(seen).toHaveBeenCalledWith("admin");
    searchParams.value = new URLSearchParams();
  });

  it("cancels a running scan and refetches", async () => {
    const cancelled = vi.fn();
    mockScan(makeScanOut({ id: 7, status: "running" }));
    server.use(
      http.post("*/api/scans/7/cancel", () => {
        cancelled();
        // from now on the API reports the scan as cancelled; only a refetch can show it
        server.use(
          http.get("*/api/scans/7", () =>
            HttpResponse.json(makeScanOut({ id: 7, status: "cancelled" })),
          ),
        );
        return new HttpResponse(null, { status: 204 });
      }),
    );
    const user = userEvent.setup();
    renderWithClient(<ScanDetailPage />);
    await screen.findByText("Running");
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(cancelled).toHaveBeenCalledTimes(1));
    // well before the 2 s poll: the refetch comes from the cancel itself
    expect(await screen.findByText("Cancelled", {}, { timeout: 1000 })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Cancel" })).not.toBeInTheDocument();
  });

  it("says so when the cancel fails", async () => {
    mockScan(makeScanOut({ id: 7, status: "running" }));
    server.use(
      http.post("*/api/scans/7/cancel", () =>
        HttpResponse.json({ detail: "scan already finished" }, { status: 409 }),
      ),
    );
    const user = userEvent.setup();
    renderWithClient(<ScanDetailPage />);
    await screen.findByText("Running");
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith("scan already finished"));
  });

  it("refetches the findings once the scan it is polling reaches a terminal status", async () => {
    let status = "running";
    const findingsCalls = vi.fn();
    const checksCalls = vi.fn();
    server.use(
      http.get("*/api/scans/7", () => HttpResponse.json(makeScanOut({ id: 7, status }))),
      http.get("*/api/scans/7/findings", () => {
        findingsCalls();
        return HttpResponse.json({
          items: status === "running" ? [] : [makeFinding({ title: "Found at the end" })],
          next_cursor: null,
          total: status === "running" ? 0 : 1,
        });
      }),
      http.get("*/api/scans/7/findings/checks", () => {
        checksCalls();
        return HttpResponse.json([]);
      }),
    );
    const { client } = renderWithClient(<ScanDetailPage />);
    await screen.findByText("Findings will appear here as the scan runs");
    expect(findingsCalls).toHaveBeenCalledTimes(1);
    expect(checksCalls).toHaveBeenCalledTimes(1);

    // what the 2 s poll does, without waiting for it: the scan comes back completed
    status = "completed";
    await client.invalidateQueries({ queryKey: keys.scans.detail(7) });

    await screen.findByText("Found at the end");
    expect(findingsCalls).toHaveBeenCalledTimes(2);
    await waitFor(() => expect(checksCalls).toHaveBeenCalledTimes(2));
  });

  it.each(["abc", "0", "-3", "1.5"])("refuses the scan id %j without asking the API", (id) => {
    // no handler at all: a request would fail the test (vitest.setup.ts)
    params.value = { id };
    renderWithClient(<ScanDetailPage />);
    expect(screen.getByText("That is not a valid scan id.")).toBeInTheDocument();
    params.value = { id: "7" };
  });

  it("tells a failed load apart from a missing scan", async () => {
    server.use(
      http.get("*/api/scans/7", () => HttpResponse.json({ detail: "boom" }, { status: 500 })),
      http.get("*/api/scans/7/findings", () =>
        HttpResponse.json({ items: [], next_cursor: null, total: 0 }),
      ),
      http.get("*/api/scans/7/findings/checks", () => HttpResponse.json([])),
    );
    renderWithClient(<ScanDetailPage />);
    await screen.findByRole("heading", { level: 1, name: "Something went wrong" });
    expect(screen.getByText("Could not load this scan.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
    expect(screen.queryByText("Scan not found")).not.toBeInTheDocument();
  });

  it("shows a retry state when only the findings fail to load", async () => {
    mockScan(makeScanOut({ id: 7, status: "completed" }));
    server.use(
      http.get("*/api/scans/7/findings", () =>
        HttpResponse.json({ detail: "boom" }, { status: 500 }),
      ),
    );
    renderWithClient(<ScanDetailPage />);
    await screen.findByText("Could not load findings.");
    expect(screen.queryByText("This scan produced no findings")).not.toBeInTheDocument();

    // Retry asks again, and a good answer replaces the failure
    server.use(
      http.get("*/api/scans/7/findings", () =>
        HttpResponse.json({ items: [makeFinding({ title: "Back" })], next_cursor: null, total: 1 }),
      ),
    );
    await userEvent.setup().click(screen.getByRole("button", { name: "Retry" }));
    await screen.findByText("Back");
    expect(screen.queryByText("Could not load findings.")).not.toBeInTheDocument();
  });

  it("shows the error of a failed scan, and only of a failed one", async () => {
    mockScan(makeScanOut({ id: 7, status: "failed", error: "target unreachable" }));
    const { unmount } = renderWithClient(<ScanDetailPage />);
    await screen.findByText("target unreachable");
    expect(screen.getByText("Error")).toBeInTheDocument();
    unmount();

    mockScan(makeScanOut({ id: 7, status: "completed", error: "stale message" }));
    const second = renderWithClient(<ScanDetailPage />);
    await screen.findByText("Completed");
    expect(screen.queryByText("stale message")).not.toBeInTheDocument();
    second.unmount();

    // a failed scan with no message gets no empty Error row
    mockScan(makeScanOut({ id: 7, status: "failed", error: null }));
    renderWithClient(<ScanDetailPage />);
    await screen.findByText("Failed");
    expect(screen.queryByText("Error")).not.toBeInTheDocument();
  });

  it("makes the hidden characters of a failed scan's error visible", async () => {
    mockScan(makeScanOut({ id: 7, status: "failed", error: "bad\u202ename\u001bx" }));
    renderWithClient(<ScanDetailPage />);

    await screen.findByText("bad\\u202ename\\x1bx");
    expect(screen.queryByText("bad\u202ename\u001bx")).not.toBeInTheDocument();
  });

  it("shows who authorized an active scan and the tool version", async () => {
    mockScan(
      makeScanOut({
        id: 7,
        status: "completed",
        mode: "active",
        authorized_by: "ticket SEC-12",
        tool_version: "1.4.5",
      }),
    );
    renderWithClient(<ScanDetailPage />);
    await screen.findByText("ticket SEC-12");
    expect(screen.getByText("Authorized by")).toBeInTheDocument();
    expect(screen.getByText("1.4.5")).toBeInTheDocument();
  });

  it("sends the severity and check filters from the URL to the API", async () => {
    const seen = vi.fn();
    searchParams.value = new URLSearchParams("severity=HIGH&check_id=headers.csp");
    mockScan(makeScanOut({ id: 7, status: "completed" }));
    server.use(
      http.get("*/api/scans/7/findings", ({ request }) => {
        const query = new URL(request.url).searchParams;
        seen(query.get("severity"), query.get("check_id"));
        return HttpResponse.json({ items: [], next_cursor: null, total: 0 });
      }),
    );
    renderWithClient(<ScanDetailPage />);
    await screen.findByText("No findings match this filter");
    expect(seen).toHaveBeenCalledWith("HIGH", "headers.csp");
    searchParams.value = new URLSearchParams();
  });

  it("says a check filter from the URL matched nothing, not that the scan found nothing", async () => {
    searchParams.value = new URLSearchParams("check_id=headers.csp");
    mockScan(makeScanOut({ id: 7, status: "completed" }), []);
    renderWithClient(<ScanDetailPage />);
    await screen.findByText("No findings match this filter");
    expect(screen.queryByText("This scan produced no findings")).not.toBeInTheDocument();
    searchParams.value = new URLSearchParams();
  });

  it("disables 'Load more' while the next page of findings loads", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    mockScan(makeScanOut({ id: 7, status: "completed" }));
    server.use(
      http.get("*/api/scans/7/findings", async ({ request }) => {
        if (new URL(request.url).searchParams.get("cursor") !== "c2") {
          return HttpResponse.json({
            items: [makeFinding({ title: "First page", fingerprint: "a" })],
            next_cursor: "c2",
            total: 2,
          });
        }
        await gate;
        return HttpResponse.json({
          items: [makeFinding({ title: "Second page", fingerprint: "b" })],
          next_cursor: null,
          total: 2,
        });
      }),
    );
    const user = userEvent.setup();
    renderWithClient(<ScanDetailPage />);
    await screen.findByText("First page");
    await user.click(screen.getByRole("button", { name: "Load more" }));
    expect(await screen.findByRole("button", { name: "Loading…" })).toBeDisabled();
    release();
    await screen.findByText("Second page");
  });

  it("counts a single finding in the singular", async () => {
    mockScan(makeScanOut({ id: 7, status: "completed" }), [makeFinding({ title: "Only one" })]);
    renderWithClient(<ScanDetailPage />);
    expect(await screen.findByText("All 1 finding shown")).toBeInTheDocument();
  });

  it("disables delete while the scan is not terminal", async () => {
    mockScan(makeScanOut({ id: 7, status: "running" }));
    renderWithClient(<ScanDetailPage />);
    await screen.findByRole("heading", { level: 1 });
    expect(screen.getByRole("button", { name: "Delete" })).toBeDisabled();
  });

  it("deletes a terminal scan and returns to the list", async () => {
    mockScan(makeScanOut({ id: 7, status: "completed" }));
    server.use(http.delete("*/api/scans/7", () => new HttpResponse(null, { status: 204 })));
    const user = userEvent.setup();
    renderWithClient(<ScanDetailPage />);
    await screen.findByRole("heading", { level: 1 });
    await user.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/scans"));
  });

  it("shows the detected-technologies section when the scan has an inventory", async () => {
    mockScan(
      makeScanOut({
        id: 7,
        status: "completed",
        technologies: [makeTechnology({ name: "jquery", version: "1.7.1", vulnerable: true })],
      }),
    );
    renderWithClient(<ScanDetailPage />);
    await screen.findByRole("heading", { name: "Detected technologies" });
    expect(screen.getByText("jquery")).toBeInTheDocument();
  });

  it("hides the detected-technologies section when there is no inventory", async () => {
    mockScan(makeScanOut({ id: 7, status: "completed", technologies: [] }));
    renderWithClient(<ScanDetailPage />);
    await screen.findByRole("heading", { level: 1 });
    expect(screen.queryByText("Detected technologies")).not.toBeInTheDocument();
  });

  it.each(["queued", "running"])(
    "does not say a %s scan produced no findings: it has not finished",
    async (status) => {
      mockScan(makeScanOut({ id: 7, status, counts: {} }), []);
      renderWithClient(<ScanDetailPage />);
      await screen.findByText("Findings will appear here as the scan runs");
      expect(screen.getByText("Scan in progress")).toBeInTheDocument();
      expect(screen.queryByText("No findings")).not.toBeInTheDocument();
      expect(screen.queryByText("This scan produced no findings")).not.toBeInTheDocument();
    },
  );

  it.each(["completed", "failed", "cancelled", "interrupted"])(
    "still says a %s scan with nothing found produced no findings",
    async (status) => {
      mockScan(makeScanOut({ id: 7, status, counts: {} }), []);
      renderWithClient(<ScanDetailPage />);
      await screen.findByText("This scan produced no findings");
      expect(screen.getByText("No findings")).toBeInTheDocument();
      expect(screen.queryByRole("table")).not.toBeInTheDocument();
    },
  );

  it("puts the target in the tab title once the scan loads", async () => {
    mockScan(makeScanOut({ id: 7, target: "https://acme.test/", status: "completed" }));
    renderWithClient(<ScanDetailPage />);
    await waitFor(() => expect(document.title).toBe("https://acme.test/ | WebVigil"));
  });

  it("shows the options as words, not as raw JSON", async () => {
    mockScan(
      makeScanOut({ id: 7, status: "completed", options: { max_pages: 12, delay_ms: 1500 } }),
    );
    renderWithClient(<ScanDetailPage />);
    await screen.findByText("max pages: 12, delay ms: 1500");
    expect(screen.queryByText(/\{"max_pages"/)).not.toBeInTheDocument();
  });

  it("distinguishes 'no match' from 'no findings'", async () => {
    searchParams.value = new URLSearchParams("severity=CRITICAL");
    mockScan(makeScanOut({ id: 7, status: "completed" }), []);
    renderWithClient(<ScanDetailPage />);
    await screen.findByText("No findings match this filter");
    searchParams.value = new URLSearchParams();
  });
});
