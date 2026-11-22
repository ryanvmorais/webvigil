import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";

import ChecksPage from "@/app/(app)/checks/page";
import { makeCheck } from "@/test/fixtures";
import { server } from "@/test/msw/server";
import { renderWithClient } from "@/test/render";

vi.mock("@/components/field-select", () => ({
  FieldSelect: ({ label, value, onValueChange, options }: any) => (
    <select aria-label={label} value={value} onChange={(e) => onValueChange(e.target.value)}>
      {options.map((o: { value: string; label: string }) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  ),
}));

const checks = [
  makeCheck({
    id: "headers.csp",
    name: "CSP header",
    category: "HEADERS",
    mode: "passive",
    default_severity: "MEDIUM",
  }),
  makeCheck({
    id: "tls.version",
    name: "TLS config",
    category: "TLS",
    mode: "passive",
    default_severity: "HIGH",
  }),
  makeCheck({
    id: "cors.wildcard",
    name: "CORS policy",
    category: "CORS",
    mode: "active",
    default_severity: "LOW",
  }),
];

describe("ChecksPage", () => {
  it("renders the catalogue and filters by category", async () => {
    const user = userEvent.setup();
    server.use(http.get("*/api/checks", () => HttpResponse.json(checks)));
    renderWithClient(<ChecksPage />);

    await screen.findByText("CSP header");
    expect(screen.getAllByRole("row")).toHaveLength(4); // header + 3
    expect(screen.queryByText("No checks registered")).not.toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Filter by category"), "TLS");
    await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(2));
    expect(screen.getByText("TLS config")).toBeInTheDocument();
    expect(screen.queryByText("CSP header")).not.toBeInTheDocument();
  });

  it("sorts by default severity when the header is toggled", async () => {
    const user = userEvent.setup();
    server.use(http.get("*/api/checks", () => HttpResponse.json(checks)));
    renderWithClient(<ChecksPage />);
    await screen.findByText("CSP header");
    const names = () =>
      screen
        .getAllByRole("row")
        .slice(1)
        .map((row) => within(row).getAllByRole("cell")[1].textContent);
    expect(names()).toEqual(["CSP header", "TLS config", "CORS policy"]); // the API's order

    await user.click(screen.getByRole("button", { name: "Default severity" }));
    expect(names()).toEqual(["TLS config", "CSP header", "CORS policy"]); // HIGH, MEDIUM, LOW

    await user.click(screen.getByRole("button", { name: /^Default severity/ }));
    expect(names()).toEqual(["CORS policy", "CSP header", "TLS config"]); // LOW, MEDIUM, HIGH

    await user.click(screen.getByRole("button", { name: /^Default severity/ }));
    expect(names()).toEqual(["CSP header", "TLS config", "CORS policy"]); // back to the API's
  });

  it("filters by mode", async () => {
    const user = userEvent.setup();
    server.use(http.get("*/api/checks", () => HttpResponse.json(checks)));
    renderWithClient(<ChecksPage />);
    await screen.findByText("CSP header");

    await user.selectOptions(screen.getByLabelText("Filter by mode"), "active");
    await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(2));
    expect(screen.getByText("CORS policy")).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Filter by mode"), "passive");
    await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(3));
    expect(screen.queryByText("CORS policy")).not.toBeInTheDocument();
  });

  it("links CWE ids and references in a new tab with no opener, and marks an empty cell", async () => {
    server.use(
      http.get("*/api/checks", () =>
        HttpResponse.json([
          makeCheck({ id: "a", name: "Linked", cwe: [79], references: ["https://example.org/r"] }),
          makeCheck({ id: "b", name: "Bare", cwe: [], references: [] }),
        ]),
      ),
    );
    renderWithClient(<ChecksPage />);
    await screen.findByText("Linked");
    const cwe = screen.getByRole("link", { name: "CWE-79" });
    expect(cwe).toHaveAttribute("href", "https://cwe.mitre.org/data/definitions/79.html");
    const ref = screen.getByRole("link", { name: "https://example.org/r" });
    expect(ref).toHaveAttribute("href", "https://example.org/r");
    for (const link of [cwe, ref]) {
      expect(link).toHaveAttribute("target", "_blank");
      expect(link).toHaveAttribute("rel", "noreferrer noopener");
    }
    const linked = screen.getByText("Linked").closest("tr") as HTMLElement;
    expect(within(linked).queryByText("—")).not.toBeInTheDocument();
    const bare = screen.getByText("Bare").closest("tr") as HTMLElement;
    expect(within(bare).getAllByText("—")).toHaveLength(2);
    expect(within(bare).queryByRole("link")).not.toBeInTheDocument();
  });

  it("starts the sort button's name with its visible text and reports the state", async () => {
    const user = userEvent.setup();
    server.use(http.get("*/api/checks", () => HttpResponse.json(checks)));
    renderWithClient(<ChecksPage />);
    await screen.findByText("CSP header");
    const header = screen.getByRole("columnheader", { name: "Default severity" });
    expect(header).not.toHaveAttribute("aria-sort");

    await user.click(screen.getByRole("button", { name: "Default severity" }));
    expect(header).toHaveAttribute("aria-sort", "descending");
    expect(
      screen.getByRole("button", { name: "Default severity, sorted descending" }),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /^Default severity/ }));
    expect(header).toHaveAttribute("aria-sort", "ascending");

    await user.click(screen.getByRole("button", { name: /^Default severity/ }));
    expect(header).not.toHaveAttribute("aria-sort");
  });

  it("scrolls inside a labelled, focusable region", async () => {
    server.use(http.get("*/api/checks", () => HttpResponse.json(checks)));
    renderWithClient(<ChecksPage />);
    await screen.findByText("CSP header");
    expect(screen.getByRole("region", { name: "Checks" })).toHaveAttribute("tabindex", "0");
  });

  it("shows a retry state on failure", async () => {
    server.use(http.get("*/api/checks", () => HttpResponse.error()));
    renderWithClient(<ChecksPage />);
    await screen.findByText(/could not load the check catalogue/i);

    server.use(http.get("*/api/checks", () => HttpResponse.json(checks)));
    await userEvent.setup().click(screen.getByRole("button", { name: "Retry" }));
    await screen.findByText("CSP header");
  });

  it("says so when the API has no checks at all", async () => {
    server.use(http.get("*/api/checks", () => HttpResponse.json([])));
    renderWithClient(<ChecksPage />);
    await screen.findByText("No checks registered");
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });
});
