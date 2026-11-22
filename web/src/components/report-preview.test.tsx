import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";

import { ReportPreview } from "@/components/report-preview";
import { server } from "@/test/msw/server";

describe("ReportPreview", () => {
  it("fetches the HTML report and mounts it in a fully sandboxed iframe via a blob URL", async () => {
    const user = userEvent.setup();
    const query: Record<string, string> = {};
    server.use(
      http.get("*/api/scans/9/report", ({ request }) => {
        new URL(request.url).searchParams.forEach((value, key) => {
          query[key] = value;
        });
        return new HttpResponse("<h1>Report</h1>", { headers: { "content-type": "text/html" } });
      }),
    );

    render(<ReportPreview scanId={9} disabled={false} />);
    await user.click(screen.getByRole("button", { name: /preview report/i }));

    const frame = await screen.findByTitle("HTML report preview");
    expect(frame).toHaveAttribute("sandbox", "");
    expect(frame).toHaveAttribute("src", "blob:mock");
    expect(query).toMatchObject({ format: "html", download: "false" });
  });

  it("announces the loading state and describes the dialog", async () => {
    const user = userEvent.setup();
    // the report is held until the test has seen the loading state: no timer to wait out
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    server.use(
      http.get("*/api/scans/9/report", async () => {
        await gate;
        return new HttpResponse("<h1>Report</h1>", { headers: { "content-type": "text/html" } });
      }),
    );

    render(<ReportPreview scanId={9} disabled={false} />);
    await user.click(screen.getByRole("button", { name: /preview report/i }));

    expect(screen.getByRole("status")).toHaveTextContent("Loading…");
    expect(screen.getByRole("dialog", { name: "HTML report" })).toHaveAccessibleDescription(
      /isolated from the rest of the page/,
    );
    release();
    await screen.findByTitle("HTML report preview");
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("shows the error instead of the frame when the report cannot be loaded", async () => {
    const user = userEvent.setup();
    server.use(
      http.get("*/api/scans/9/report", () =>
        HttpResponse.json({ detail: "scan is still running" }, { status: 409 }),
      ),
    );
    render(<ReportPreview scanId={9} disabled={false} />);
    await user.click(screen.getByRole("button", { name: /preview report/i }));

    expect(await screen.findByText("scan is still running")).toBeInTheDocument();
    expect(screen.queryByTitle("HTML report preview")).not.toBeInTheDocument();
    expect(screen.queryByText("Loading…")).not.toBeInTheDocument();
  });

  it("revokes the blob URL on close and starts clean when opened again", async () => {
    const user = userEvent.setup();
    const revoke = vi.spyOn(URL, "revokeObjectURL");
    let fail = true;
    server.use(
      http.get("*/api/scans/9/report", () =>
        fail
          ? HttpResponse.json({ detail: "first try failed" }, { status: 500 })
          : new HttpResponse("<h1>Report</h1>", { headers: { "content-type": "text/html" } }),
      ),
    );
    render(<ReportPreview scanId={9} disabled={false} />);

    await user.click(screen.getByRole("button", { name: /preview report/i }));
    await screen.findByText("first try failed");
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());

    fail = false;
    await user.click(screen.getByRole("button", { name: /preview report/i }));
    await screen.findByTitle("HTML report preview");
    expect(screen.queryByText("first try failed")).not.toBeInTheDocument();
    expect(revoke).not.toHaveBeenCalled();

    await user.keyboard("{Escape}");
    await waitFor(() => expect(revoke).toHaveBeenCalledWith("blob:mock"));
  });

  it("disables the trigger when there is nothing to preview", () => {
    render(<ReportPreview scanId={9} disabled />);
    expect(screen.getByRole("button", { name: /preview report/i })).toBeDisabled();
  });
});
