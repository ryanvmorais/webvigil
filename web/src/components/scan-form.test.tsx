import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ScanForm } from "@/components/scan-form";
import { makeCheck } from "@/test/fixtures";
import { server } from "@/test/msw/server";
import { renderWithClient } from "@/test/render";

const { router } = vi.hoisted(() => ({
  router: {
    push: vi.fn(),
    replace: vi.fn(),
    prefetch: vi.fn(),
    refresh: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
  },
}));
vi.mock("next/navigation", () => ({
  useRouter: () => router,
  usePathname: () => "/scans/new",
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock("@/components/field-select", () => ({
  FieldSelect: ({ label, value, onValueChange, options, id }: any) => (
    <select
      aria-label={label}
      id={id}
      value={value}
      onChange={(e) => onValueChange(e.target.value)}
    >
      {options.map((o: { value: string; label: string }) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  ),
}));

const defaults = {
  mode: "passive",
  scope: "host",
  max_pages: 25,
  delay_ms: 300,
  follow_robots: true,
  fail_on: "medium",
};

beforeEach(() => {
  server.use(
    http.get("*/api/config/defaults", () => HttpResponse.json(defaults)),
    http.get("*/api/checks", () =>
      HttpResponse.json([
        makeCheck({ id: "headers.csp", name: "CSP" }),
        makeCheck({ id: "tls.version", name: "TLS version" }),
      ]),
    ),
  );
});

describe("ScanForm", () => {
  it("pre-fills from /api/config/defaults", async () => {
    renderWithClient(<ScanForm />);
    await waitFor(() => expect(screen.getByLabelText("Max pages")).toHaveValue(25));
    expect(screen.getByLabelText("Delay between requests (ms)")).toHaveValue(300);
  });

  it("blocks an active scan with no authorization and shows the warning", async () => {
    const user = userEvent.setup();
    const posted = vi.fn();
    server.use(
      http.post("*/api/scans", () => {
        posted();
        return HttpResponse.json({}, { status: 201 });
      }),
    );

    renderWithClient(<ScanForm />);
    await screen.findByLabelText("Max pages");
    await user.type(screen.getByLabelText("Target"), "https://example.com");
    await user.selectOptions(screen.getByLabelText("Mode"), "active");

    expect(screen.getByRole("alert")).toHaveTextContent(/potentially intrusive traffic/i);

    await user.click(screen.getByRole("button", { name: "Start scan" }));
    expect(
      await screen.findByText("Active scans require an authorization attestation."),
    ).toBeInTheDocument();
    expect(posted).not.toHaveBeenCalled();
  });

  it("lists the check catalogue in the disabled-checks control", async () => {
    const user = userEvent.setup();
    renderWithClient(<ScanForm />);
    await screen.findByLabelText("Max pages");
    await user.click(screen.getByRole("button", { name: /disabled checks/i }));
    expect(await screen.findByText("headers.csp")).toBeInTheDocument();
    expect(screen.getByText("tls.version")).toBeInTheDocument();
  });

  it("maps a server 422 back onto the target field", async () => {
    const user = userEvent.setup();
    server.use(
      http.post("*/api/scans", () =>
        HttpResponse.json(
          { detail: [{ loc: ["body", "target"], msg: "unsupported scheme", type: "value_error" }] },
          { status: 422 },
        ),
      ),
    );
    renderWithClient(<ScanForm />);
    await screen.findByLabelText("Max pages");
    await user.type(screen.getByLabelText("Target"), "https://example.com");
    await user.click(screen.getByRole("button", { name: "Start scan" }));
    expect(await screen.findByText("unsupported scheme")).toBeInTheDocument();
  });

  it("submits a valid passive scan and routes to its detail view", async () => {
    const user = userEvent.setup();
    let body: any;
    server.use(
      http.post("*/api/scans", async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ id: 42 }, { status: 201 });
      }),
    );
    renderWithClient(<ScanForm />);
    await screen.findByLabelText("Max pages");
    await user.type(screen.getByLabelText("Target"), "https://example.com");
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    await waitFor(() => expect(router.push).toHaveBeenCalledWith("/scans/42"));
    expect(body).toMatchObject({ target: "https://example.com", mode: "passive", max_pages: 25 });
    expect(body).not.toHaveProperty("authorized_by");
  });
});
