import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";

import ScanDetailPage from "@/app/(app)/scans/[id]/page";
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
vi.mock("@/components/report-menu", () => ({ ReportMenu: () => null }));
vi.mock("@/components/report-preview", () => ({ ReportPreview: () => null }));

function mockScan(scan: Record<string, unknown>, findings: unknown[] = []) {
  server.use(
    http.get("*/api/scans/7", () => HttpResponse.json(scan)),
    http.get("*/api/scans/7/findings", () => HttpResponse.json(findings)),
    http.get("*/api/checks", () => HttpResponse.json([])),
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
  });

  it("renders a not-found state for a missing scan", async () => {
    server.use(
      http.get("*/api/scans/7", () =>
        HttpResponse.json({ detail: "scan not found" }, { status: 404 }),
      ),
      http.get("*/api/scans/7/findings", () => HttpResponse.json([])),
      http.get("*/api/checks", () => HttpResponse.json([])),
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
  });

  it("cancels a running scan and refetches", async () => {
    const cancelled = vi.fn();
    mockScan(makeScanOut({ id: 7, status: "running" }));
    server.use(
      http.post("*/api/scans/7/cancel", () => {
        cancelled();
        return new HttpResponse(null, { status: 204 });
      }),
    );
    const user = userEvent.setup();
    renderWithClient(<ScanDetailPage />);
    await screen.findByRole("heading", { level: 1 });
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(cancelled).toHaveBeenCalled());
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
