/* eslint-disable @typescript-eslint/no-explicit-any */
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
  it("is disabled until the scan can produce a report", () => {
    render(<ReportMenu scanId={5} status="running" />);
    expect(screen.getByRole("button", { name: /report/i })).toBeDisabled();
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
