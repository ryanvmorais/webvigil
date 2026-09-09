import { screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";

import {
  makeCheck,
  makeFinding,
  makeScanOut,
  makeScanSummary,
  makeTechnology,
} from "@/test/fixtures";
import { axe, noSeriousViolations } from "@/test/axe";
import { server } from "@/test/msw/server";
import { renderWithClient } from "@/test/render";

const { searchParams, params } = vi.hoisted(() => ({
  searchParams: { value: new URLSearchParams() },
  params: { value: { id: "7" } as Record<string, string> },
}));
vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn(), prefetch: vi.fn(), refresh: vi.fn() }),
  usePathname: () => "/",
  useParams: () => params.value,
  useSearchParams: () => searchParams.value,
}));
vi.mock("@/components/field-select", () => ({
  FieldSelect: ({ label, value, onValueChange, options, id }: any) => (
    <select
      aria-label={label}
      id={id}
      value={value}
      onChange={(e) => onValueChange(e.target.value)}
    >
      {options.map((o: { value: string; label: string }) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  ),
}));

async function assertClean(container: HTMLElement) {
  const results = await axe(container);
  expect(noSeriousViolations(results)).toEqual([]);
}

describe("accessibility (no serious/critical axe violations)", () => {
  it("login", async () => {
    const { default: LoginPage } = await import("@/app/(auth)/login/page");
    const { container } = renderWithClient(<LoginPage />);
    await screen.findByLabelText("Username");
    await assertClean(container);
  });

  it("setup", async () => {
    const { default: SetupPage } = await import("@/app/(auth)/setup/page");
    const { container } = renderWithClient(<SetupPage />);
    await screen.findByLabelText("Username");
    await assertClean(container);
  });

  it("scan list", async () => {
    server.use(
      http.get("*/api/scans", () =>
        HttpResponse.json({ items: [makeScanSummary()], next_cursor: null }),
      ),
    );
    const { default: ScansPage } = await import("@/app/(app)/scans/page");
    const { container } = renderWithClient(<ScansPage />);
    await screen.findByRole("table");
    await assertClean(container);
  });

  it("new scan", async () => {
    server.use(
      http.get("*/api/config/defaults", () =>
        HttpResponse.json({
          mode: "passive",
          scope: "host",
          max_pages: 25,
          delay_ms: 200,
          follow_robots: true,
          fail_on: "medium",
        }),
      ),
      http.get("*/api/checks", () => HttpResponse.json([makeCheck()])),
    );
    const { default: NewScanPage } = await import("@/app/(app)/scans/new/page");
    const { container } = renderWithClient(<NewScanPage />);
    await screen.findByLabelText("Target");
    await assertClean(container);
  });

  it("scan detail", async () => {
    server.use(
      http.get("*/api/scans/7", () =>
        HttpResponse.json(
          makeScanOut({
            id: 7,
            status: "completed",
            technologies: [makeTechnology()],
          }),
        ),
      ),
      http.get("*/api/scans/7/findings", () => HttpResponse.json([makeFinding()])),
      http.get("*/api/checks", () => HttpResponse.json([makeCheck()])),
    );
    const { default: ScanDetailPage } = await import("@/app/(app)/scans/[id]/page");
    const { container } = renderWithClient(<ScanDetailPage />);
    await screen.findByRole("heading", { level: 1 });
    await screen.findByRole("heading", { name: "Detected technologies" });
    await waitFor(() => expect(screen.getAllByRole("table").length).toBeGreaterThan(0));
    await assertClean(container);
  });

  it("checks catalogue", async () => {
    server.use(http.get("*/api/checks", () => HttpResponse.json([makeCheck()])));
    const { default: ChecksPage } = await import("@/app/(app)/checks/page");
    const { container } = renderWithClient(<ChecksPage />);
    await screen.findByRole("table");
    await assertClean(container);
  });

  it("settings", async () => {
    server.use(http.get("*/api/health", () => HttpResponse.json({ status: "ok", version: "0" })));
    const { default: SettingsPage } = await import("@/app/(app)/settings/page");
    const { container } = renderWithClient(<SettingsPage />);
    await screen.findByLabelText("Current password");
    await assertClean(container);
  });
});
