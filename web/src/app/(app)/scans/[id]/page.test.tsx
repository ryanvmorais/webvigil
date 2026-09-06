/* eslint-disable @typescript-eslint/no-explicit-any */
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";

import ScanDetailPage from "@/app/(app)/scans/[id]/page";
import { makeFinding, makeScanOut } from "@/test/fixtures";
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
    await screen.findByText("Scan not found");
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

  it("distinguishes 'no match' from 'no findings'", async () => {
    searchParams.value = new URLSearchParams("severity=CRITICAL");
    mockScan(makeScanOut({ id: 7, status: "completed" }), []);
    renderWithClient(<ScanDetailPage />);
    await screen.findByText("No findings match this filter");
    searchParams.value = new URLSearchParams();
  });
});
