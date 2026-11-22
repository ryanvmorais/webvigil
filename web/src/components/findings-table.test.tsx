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

  it("shows bidirectional and zero-width characters from the site as escapes", async () => {
    const user = userEvent.setup();
    const rlo = String.fromCodePoint(0x202e);
    const zwsp = String.fromCodePoint(0x200b);
    render(
      <FindingsTable
        findings={[
          makeFinding({
            fingerprint: "z",
            title: `Reflected in ${rlo}fdp.exe`,
            evidence: [{ label: `cookie ad${zwsp}min`, content: `a${rlo}b` }],
          }),
        ]}
      />,
    );
    expect(screen.getByText("Reflected in \\u202efdp.exe")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /^Expand finding:/ }));

    expect(screen.getByText("cookie ad\\u200bmin")).toBeInTheDocument();
    expect(screen.getByText("a\\u202eb")).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(rlo);
    expect(document.body.textContent).not.toContain(zwsp);
  });

  it("escapes them in every field the site can reach, not only the title and the evidence", async () => {
    const user = userEvent.setup();
    const rlo = String.fromCodePoint(0x202e);
    render(
      <FindingsTable
        findings={[
          makeFinding({
            fingerprint: "all",
            description: `desc${rlo}`,
            remediation: `fix${rlo}`,
            location: {
              url: `https://example.com/${rlo}`,
              method: "GET",
              param: `p${rlo}`,
              header: null,
              cookie: null,
            },
            references: [`urn:${rlo}x`],
          }),
          makeFinding({
            fingerprint: "cookie",
            location: {
              url: "https://example.com/",
              method: "GET",
              param: null,
              header: null,
              cookie: `sid${rlo}`,
            },
          }),
        ]}
      />,
    );
    for (const button of screen.getAllByRole("button", { name: /^Expand finding:/ })) {
      await user.click(button);
    }
    expect(screen.getByText("desc\\u202e")).toBeInTheDocument();
    expect(screen.getByText("fix\\u202e")).toBeInTheDocument();
    expect(screen.getByText("urn:\\u202ex")).toBeInTheDocument();
    expect(screen.getAllByText("https://example.com/\\u202e · param p\\u202e")).toHaveLength(2);
    expect(screen.getAllByText("https://example.com/ · cookie sid\\u202e")).toHaveLength(2);
    expect(document.body.textContent).not.toContain(rlo);
  });

  it("keeps the one-line fields on one line, and lets a description and evidence break", async () => {
    const user = userEvent.setup();
    render(
      <FindingsTable
        findings={[
          makeFinding({
            fingerprint: "nl",
            title: "Title\nforged second line",
            description: "first\nsecond",
            location: {
              url: "https://example.com/a\nb",
              method: "GET",
              param: null,
              header: null,
              cookie: null,
            },
            evidence: [{ label: "Label\nforged", content: "line 1\nline 2" }],
            references: ["urn:a\nb"],
          }),
        ]}
      />,
    );
    expect(screen.getByText("Title\\x0aforged second line")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /^Expand finding:/ }));
    expect(screen.getAllByText("https://example.com/a\\x0ab")).toHaveLength(2);
    expect(screen.getByText("Label\\x0aforged")).toBeInTheDocument();
    expect(screen.getByText("urn:a\\x0ab")).toBeInTheDocument();
    // a body keeps its line breaks: only the single-line fields escape them
    const description = screen.getByText((_, el) => el?.textContent === "first\nsecond");
    expect(description.tagName).toBe("P");
    expect(screen.getByText((_, el) => el?.textContent === "line 1\nline 2").tagName).toBe("PRE");
  });

  it("opens every outside link in a new tab with no opener and no referrer", async () => {
    const user = userEvent.setup();
    render(
      <FindingsTable
        findings={[
          makeFinding({ fingerprint: "l", cwe: [79], references: ["https://example.org/ref"] }),
        ]}
      />,
    );
    await user.click(screen.getByRole("button", { name: /^Expand finding:/ }));
    for (const name of ["CWE-79", "https://example.org/ref"]) {
      const link = screen.getByRole("link", { name });
      expect(link).toHaveAttribute("target", "_blank");
      expect(link).toHaveAttribute("rel", "noreferrer noopener");
    }
  });

  it("collapses an open row on a second click", async () => {
    const user = userEvent.setup();
    render(<FindingsTable findings={[makeFinding({ title: "One", fingerprint: "x" })]} />);
    await user.click(screen.getByRole("button", { name: "Expand finding: One" }));
    expect(screen.getByText("Remediation.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Collapse finding: One" }));
    expect(screen.queryByText("Remediation.")).not.toBeInTheDocument();
  });

  it("leaves out the CWE and reference blocks when a finding has none", async () => {
    const user = userEvent.setup();
    render(
      <FindingsTable findings={[makeFinding({ fingerprint: "e", cwe: [], references: [] })]} />,
    );
    await user.click(screen.getByRole("button", { name: /^Expand finding:/ }));
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    expect(screen.queryByRole("list")).not.toBeInTheDocument();
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
