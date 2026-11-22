import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ReportMenu } from "@/components/report-menu";

vi.mock("@/components/ui/dropdown-menu", () => ({
  DropdownMenu: ({ children }: any) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: any) => <>{children}</>,
  DropdownMenuContent: ({ children }: any) => <div>{children}</div>,
  DropdownMenuItem: ({ children }: any) => <>{children}</>,
}));

describe("ReportMenu", () => {
  it.each(["queued", "running", "failed", "cancelled"])(
    "is disabled for a %s scan, which has no report, and says why in a tooltip",
    (status) => {
      render(<ReportMenu scanId={5} status={status} />);
      const button = screen.getByRole("button", { name: /report/i });
      expect(button).toBeDisabled();
      expect(button).toHaveAttribute("title", "Available once the scan completes");
    },
  );

  it.each(["completed", "interrupted"])("is enabled for a %s scan", (status) => {
    render(<ReportMenu scanId={5} status={status} />);
    const button = screen.getByRole("button", { name: "Report" });
    expect(button).toBeEnabled();
    expect(button).not.toHaveAttribute("title");
  });

  it("says why it is disabled in its name, not only in a tooltip a phone never shows", () => {
    render(<ReportMenu scanId={5} status="running" />);
    expect(
      screen.getByRole("button", { name: "Report: available once the scan completes" }),
    ).toBeInTheDocument();
  });

  it("is just 'Report' once it works", () => {
    render(<ReportMenu scanId={5} status="completed" />);
    expect(screen.getByRole("button", { name: "Report" })).toBeEnabled();
  });

  it("offers all four formats as attachment downloads", () => {
    render(<ReportMenu scanId={5} status="completed" />);
    expect(screen.getByRole("button", { name: /report/i })).toBeEnabled();
    for (const format of ["json", "sarif", "html", "md"]) {
      const link = screen.getByRole("link", { name: format.toUpperCase() });
      expect(link).toHaveAttribute("href", `/api/scans/5/report?format=${format}&download=true`);
      expect(link).toHaveAttribute("download");
    }
  });
});
