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

    await user.click(screen.getByRole("button", { name: /^Expand finding:/ }));

    expect(screen.getByText("Add the header.")).toBeInTheDocument();
    expect(screen.getByText("Raw headers")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "CWE-693" })).toHaveAttribute(
      "href",
      "https://cwe.mitre.org/data/definitions/693.html",
    );
    expect(screen.getByRole("link", { name: "https://example.org/ref" })).toBeInTheDocument();
  });

  it("links an http(s) reference and shows any other scheme as plain text (#161)", async () => {
    const user = userEvent.setup();
    render(
      <FindingsTable
        findings={[
          makeFinding({
            fingerprint: "y",
            references: ["https://example.org/ok", "javascript:alert(1)", "data:text/html,x"],
          }),
        ]}
      />,
    );
    await user.click(screen.getByRole("button", { name: /^Expand finding:/ }));

    expect(screen.getByRole("link", { name: "https://example.org/ok" })).toHaveAttribute(
      "href",
      "https://example.org/ok",
    );
    expect(screen.getByText("javascript:alert(1)")).toBeInTheDocument();
    expect(screen.getByText("data:text/html,x")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "javascript:alert(1)" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "data:text/html,x" })).not.toBeInTheDocument();
  });

  it("names each expand button after its finding, so a screen reader can tell them apart", () => {
    render(
      <FindingsTable
        findings={[
          makeFinding({ title: "CSP header is missing", fingerprint: "a" }),
          makeFinding({ title: "Cookie lacks HttpOnly", fingerprint: "b" }),
        ]}
      />,
    );
    const names = screen.getAllByRole("button").map((button) => button.getAttribute("aria-label"));
    expect(names).toEqual([
      "Expand finding: CSP header is missing",
      "Expand finding: Cookie lacks HttpOnly",
    ]);
  });

  it("points aria-controls at the detail row, and only while it exists", async () => {
    const user = userEvent.setup();
    render(<FindingsTable findings={[makeFinding({ title: "One", fingerprint: "x" })]} />);
    const button = screen.getByRole("button", { name: "Expand finding: One" });
    expect(button).not.toHaveAttribute("aria-controls");

    await user.click(button);

    const opened = screen.getByRole("button", { name: "Collapse finding: One" });
    const detail = document.getElementById(opened.getAttribute("aria-controls") as string);
    expect(detail).toHaveTextContent("Remediation.");
  });

  it("gives the truncated location a tooltip and repeats it in the expanded detail", async () => {
    const user = userEvent.setup();
    const location = {
      url: "https://example.com/a",
      method: "GET",
      param: null,
      header: "Access-Control-Allow-Origin",
      cookie: null,
    };
    render(<FindingsTable findings={[makeFinding({ fingerprint: "l", location })]} />);
    const full = "https://example.com/a · header Access-Control-Allow-Origin";

    expect(screen.getByTitle(full)).toHaveClass("truncate");
    expect(screen.queryByText("Location.")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /^Expand finding:/ }));

    expect(screen.getByText("Location.")).toBeInTheDocument();
    expect(screen.getAllByText(full)).toHaveLength(2);
  });

  it("scrolls inside a labelled, focusable region reachable by keyboard", () => {
    render(<FindingsTable findings={[makeFinding({ fingerprint: "r" })]} />);
    expect(screen.getByRole("region", { name: "Findings" })).toHaveAttribute("tabindex", "0");
  });

  it("grows the expand button's touch target to 44 px without growing the row", () => {
    // 16 px icon + 2 x 14 px padding = 44 px; the -14 px margin gives the space back
    render(<FindingsTable findings={[makeFinding({ fingerprint: "t" })]} />);
    const button = screen.getByRole("button", { name: /^Expand finding:/ });
    expect(button).toHaveClass("p-3.5", "-m-3.5");
  });
});
