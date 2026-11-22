import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ConfidenceBadge } from "@/components/confidence-badge";
import { ModeBadge } from "@/components/mode-badge";
import { SeverityBadge } from "@/components/severity-badge";
import { SeveritySummary } from "@/components/severity-summary";
import { StatusBadge } from "@/components/status-badge";

describe("SeverityBadge", () => {
  it.each([
    ["INFO", "Info"],
    ["LOW", "Low"],
    ["MEDIUM", "Medium"],
    ["HIGH", "High"],
    ["CRITICAL", "Critical"],
  ])("labels %s as %s", (severity, label) => {
    render(<SeverityBadge severity={severity} />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });

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
  it.each([
    ["queued", "Queued"],
    ["running", "Running"],
    ["completed", "Completed"],
    ["failed", "Failed"],
    ["cancelled", "Cancelled"],
    ["interrupted", "Interrupted"],
  ])("labels the status %s in words", (status, label) => {
    const { container } = render(<StatusBadge status={status} />);
    expect(screen.getByText(label)).toBeInTheDocument();
    expect(container.querySelector("svg")).toBeTruthy();
  });

  it("spins the icon only while the scan runs", () => {
    const { container, rerender } = render(<StatusBadge status="running" />);
    expect(container.querySelector("svg")).toHaveClass("animate-spin");
    rerender(<StatusBadge status="queued" />);
    expect(container.querySelector("svg")).not.toHaveClass("animate-spin");
  });

  it("shows a status it does not know as it came, with an icon", () => {
    const { container } = render(<StatusBadge status="paused" />);
    expect(screen.getByText("paused")).toBeInTheDocument();
    expect(container.querySelector("svg")).toBeTruthy();
  });
});

describe("ConfidenceBadge", () => {
  it.each([
    ["LOW", "Low confidence"],
    ["MEDIUM", "Medium confidence"],
    ["HIGH", "High confidence"],
  ])("spells out the confidence level %s", (confidence, label) => {
    render(<ConfidenceBadge confidence={confidence} />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });

  it("spells out a level it does not know", () => {
    render(<ConfidenceBadge confidence="CERTAIN" />);
    expect(screen.getByText("CERTAIN confidence")).toBeInTheDocument();
  });
});

describe("ModeBadge", () => {
  it("tells an active scan apart from a passive one", () => {
    const { rerender } = render(<ModeBadge mode="active" />);
    expect(screen.getByText("Active")).toHaveClass("text-severity-high");
    rerender(<ModeBadge mode="passive" />);
    expect(screen.getByText("Passive")).not.toHaveClass("text-severity-high");
  });
});

describe("SeveritySummary", () => {
  it("orders all five severities from the highest", () => {
    render(<SeveritySummary counts={{ INFO: 5, LOW: 4, MEDIUM: 3, HIGH: 2, CRITICAL: 1 }} />);
    const items = screen.getAllByRole("listitem").map((li) => li.textContent);
    expect(items).toEqual(["1 critical", "2 high", "3 medium", "4 low", "5 info"]);
  });

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
