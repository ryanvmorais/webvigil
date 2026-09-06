import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";

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

  it("disables the trigger when there is nothing to preview", () => {
    render(<ReportPreview scanId={9} disabled />);
    expect(screen.getByRole("button", { name: /preview report/i })).toBeDisabled();
  });
});
