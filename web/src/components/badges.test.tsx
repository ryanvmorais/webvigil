import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ConfidenceBadge } from "@/components/confidence-badge";
import { SeverityBadge } from "@/components/severity-badge";
import { SeveritySummary } from "@/components/severity-summary";
import { StatusBadge } from "@/components/status-badge";

describe("SeverityBadge", () => {
  it("shows a text label (not colour alone) and an icon", () => {
    const { container } = render(<SeverityBadge severity="HIGH" />);
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(container.querySelector("svg")).toBeTruthy();
  });

  it("falls back to Info for an unknown severity", () => {
    render(<SeverityBadge severity="???" />);
    expect(screen.getByText("Info")).toBeInTheDocument();
  });
});

describe("StatusBadge", () => {
  it("labels each status in words", () => {
    render(<StatusBadge status="interrupted" />);
    expect(screen.getByText("Interrupted")).toBeInTheDocument();
  });
});

describe("ConfidenceBadge", () => {
  it("spells out the confidence level", () => {
    render(<ConfidenceBadge confidence="MEDIUM" />);
    expect(screen.getByText("Medium confidence")).toBeInTheDocument();
  });
});

describe("SeveritySummary", () => {
  it("renders one chip per non-zero severity, highest first", () => {
    render(<SeveritySummary counts={{ INFO: 0, LOW: 1, MEDIUM: 0, HIGH: 2, CRITICAL: 0 }} />);
    const items = screen.getAllByRole("listitem").map((li) => li.textContent);
    expect(items).toEqual(["2 high", "1 low"]);
  });

  it("says so when there are no findings", () => {
    render(<SeveritySummary counts={{}} />);
    expect(screen.getByText("No findings")).toBeInTheDocument();
  });

  it("does not call a scan that is still running clean", () => {
    render(<SeveritySummary counts={{}} inProgress />);
    expect(screen.getByText("Scan in progress")).toBeInTheDocument();
    expect(screen.queryByText("No findings")).not.toBeInTheDocument();
  });

  it("still shows the chips of a running scan that has found something", () => {
    render(<SeveritySummary counts={{ HIGH: 1 }} inProgress />);
    expect(screen.getByRole("listitem")).toHaveTextContent("1 high");
  });

  it("keeps each chip on one line, so a narrow column does not split '6 / medium'", () => {
    render(<SeveritySummary counts={{ HIGH: 2, LOW: 1 }} />);
    for (const chip of screen.getAllByRole("listitem"))
      expect(chip).toHaveClass("whitespace-nowrap");
  });
});
