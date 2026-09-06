/* eslint-disable @typescript-eslint/no-explicit-any */
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

    await user.click(screen.getByRole("button", { name: /sort by default severity/i }));
    const firstRowAfterHeader = screen.getAllByRole("row")[1];
    expect(within(firstRowAfterHeader).getByText("TLS config")).toBeInTheDocument(); // HIGH first (desc)
  });

  it("shows a retry state on failure", async () => {
    server.use(http.get("*/api/checks", () => HttpResponse.error()));
    renderWithClient(<ChecksPage />);
    await screen.findByText(/could not load the check catalogue/i);
  });
});
