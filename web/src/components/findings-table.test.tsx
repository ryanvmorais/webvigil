import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { FindingsTable } from "@/components/findings-table";
import { makeFinding } from "@/test/fixtures";

describe("FindingsTable", () => {
  it("renders rows in the order given, without re-sorting", () => {
    render(
      <FindingsTable
        findings={[
          makeFinding({ title: "First (low)", severity: "LOW", fingerprint: "a" }),
          makeFinding({ title: "Second (critical)", severity: "CRITICAL", fingerprint: "b" }),
        ]}
      />,
    );
    const titles = screen
      .getAllByRole("row")
      .slice(1)
      .map((row) => row.textContent);
    expect(titles[0]).toContain("First (low)");
    expect(titles[1]).toContain("Second (critical)");
  });

  it("expands a row to show remediation, evidence, CWE and references", async () => {
    const user = userEvent.setup();
    render(
      <FindingsTable
        findings={[
          makeFinding({
            fingerprint: "x",
            remediation: "Add the header.",
            evidence: [{ label: "Raw headers", content: "server: nginx" }],
            cwe: [693],
            references: ["https://example.org/ref"],
          }),
        ]}
      />,
    );
    expect(screen.queryByText("Add the header.")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Expand finding" }));

    expect(screen.getByText("Add the header.")).toBeInTheDocument();
    expect(screen.getByText("Raw headers")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "CWE-693" })).toHaveAttribute(
      "href",
      "https://cwe.mitre.org/data/definitions/693.html",
    );
    expect(screen.getByRole("link", { name: "https://example.org/ref" })).toBeInTheDocument();
  });
});
