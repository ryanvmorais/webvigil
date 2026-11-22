/**
 * The scan list table (RF-11): which columns survive on a phone, the labelled scroll region,
 * and the summary of a scan that has not finished.
 *
 * Nothing is mocked. jsdom has no layout and applies no media query, so the responsive rule
 * is pinned as the Tailwind classes that implement it (`hidden sm:table-cell`); the measured
 * effect (534 px of table in a 340 px window, down to 340) came from a real browser run.
 */
import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ScanListTable } from "@/components/scan-list-table";
import { makeScanSummary } from "@/test/fixtures";

const HIDDEN_ON_PHONE = ["Mode", "Scope", "Created"];
const ALWAYS_SHOWN = ["Target", "Status", "Findings"];

describe("ScanListTable", () => {
  it.each(HIDDEN_ON_PHONE)("hides the %s column below the sm breakpoint", (name) => {
    render(<ScanListTable scans={[makeScanSummary()]} />);
    const header = screen.getByRole("columnheader", { name });
    expect(header).toHaveClass("hidden", "sm:table-cell");

    const index = Array.from(header.parentElement!.children).indexOf(header);
    const cell = within(screen.getAllByRole("row")[1]).getAllByRole("cell")[index];
    expect(cell).toHaveClass("hidden", "sm:table-cell");
  });

  it.each(ALWAYS_SHOWN)("keeps the %s column on a phone", (name) => {
    render(<ScanListTable scans={[makeScanSummary()]} />);
    expect(screen.getByRole("columnheader", { name })).not.toHaveClass("hidden");
  });

  it("scrolls inside a labelled, focusable region", () => {
    render(<ScanListTable scans={[makeScanSummary()]} />);
    expect(screen.getByRole("region", { name: "Scans" })).toHaveAttribute("tabindex", "0");
  });

  it("does not say a queued or running scan has no findings", () => {
    render(
      <ScanListTable
        scans={[
          makeScanSummary({ id: 1, status: "running", counts: {} }),
          makeScanSummary({ id: 2, status: "completed", counts: {} }),
        ]}
      />,
    );
    // per row: two swapped labels would still count one of each
    const [running, completed] = screen.getAllByRole("row").slice(1);
    expect(within(running).getByText("Scan in progress")).toBeInTheDocument();
    expect(within(running).queryByText("No findings")).not.toBeInTheDocument();
    expect(within(completed).getByText("No findings")).toBeInTheDocument();
    expect(within(completed).queryByText("Scan in progress")).not.toBeInTheDocument();
  });
});
