/**
 * The dashboard's gate for spec 025 (RF-07, RF-09, ADR-8): every page is rendered from API
 * payloads whose strings, at any depth, carry an escape, a C1 control, a bidirectional override
 * and a zero-width space, and no such character may reach the page's text, an attribute or the
 * document title. The helper fills every string, so a field the API gains later is covered too.
 */
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it, vi } from "vitest";

import ChecksPage from "@/app/(app)/checks/page";
import ScansPage from "@/app/(app)/scans/page";
import ScanDetailPage from "@/app/(app)/scans/[id]/page";
import { ReportPreview } from "@/components/report-preview";
import { ScanForm } from "@/components/scan-form";
import {
  makeCheck,
  makeFinding,
  makeScanOut,
  makeScanSummary,
  makeTechnology,
} from "@/test/fixtures";
import { server } from "@/test/msw/server";
import { renderWithClient } from "@/test/render";

const { search } = vi.hoisted(() => ({ search: { value: new URLSearchParams() } }));
vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: vi.fn(),
    replace: vi.fn(),
    prefetch: vi.fn(),
    refresh: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
  }),
  useParams: () => ({ id: "7" }),
  usePathname: () => "/scans/7",
  useSearchParams: () => search.value,
}));
// The real select shows its options only while open; this one lists every label a page passes,
// so the filters' labels are on the page to check. It renders no `value`, as the real one does
// not outside a form.
vi.mock("@/components/field-select", () => ({
  FieldSelect: ({ label, options }: { label: string; options: { label: string }[] }) => (
    <ul aria-label={label}>
      {options.map((option, index) => (
        <li key={index}>{option.label}</li>
      ))}
    </ul>
  ),
}));

// ESC, the C1 CSI, RIGHT-TO-LEFT OVERRIDE and ZERO WIDTH SPACE: one of each kind the
// neutralization escapes. Built from code points so this file holds none of them raw.
const INJECTED = [0x1b, 0x9b, 0x202e, 0x200b].map((code) => String.fromCodePoint(code));
const HOSTILE = `${INJECTED[0]}[2J${INJECTED.slice(1).join("")}`;

// The values of these keys are the API's own, not text a site, a file or a user chose: an enum
// of its schema, a timestamp it writes, the engine's hex digest for `fingerprint`, and the field
// path of a `422` (`loc`), which names a field of the request model. The pages also branch on
// them: a scan whose status is not `failed` would hide the error row under test.
const FIXED_KEYS: ReadonlySet<string> = new Set([
  "status",
  "mode",
  "scope",
  "severity",
  "default_severity",
  "confidence",
  "fail_on",
  "fingerprint",
  "created_at",
  "started_at",
  "finished_at",
  "loc",
]);

/** The payload with every string, at any depth, followed by the hostile characters. */
function hostile<T>(value: T, key?: string): T {
  if (typeof value === "string") {
    return (key !== undefined && FIXED_KEYS.has(key) ? value : `${value}${HOSTILE}`) as T;
  }
  if (Array.isArray(value)) return value.map((item) => hostile(item, key)) as T;
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([name, item]) => [name, hostile(item, name)]),
    ) as T;
  }
  return value;
}

/** Every injected character found in the page's text, its attributes and the document title. */
function rawCharactersOnPage(): string[] {
  const places = [document.title, document.body.textContent ?? ""];
  for (const element of document.body.querySelectorAll("*")) {
    for (const attribute of element.attributes) places.push(attribute.value);
  }
  const found: string[] = [];
  for (const place of places) {
    for (const char of INJECTED) {
      const at = place.indexOf(char);
      if (at === -1) continue;
      // a short window of the place, with the characters spelled out, names the field
      const around = [...place.slice(Math.max(0, at - 30), at + 10)]
        .map((c) => (INJECTED.includes(c) ? `<U+${c.codePointAt(0)?.toString(16)}>` : c))
        .join("");
      found.push(around);
    }
  }
  return found;
}

/** Fails with the places that hold a raw character, after checking the page shows the payload. */
function expectNothingRaw() {
  // the positive control: the payload did reach the page, as visible escapes
  expect(document.body.textContent).toContain("\\x1b[2J\\x9b\\u202e\\u200b");
  expect(rawCharactersOnPage()).toEqual([]);
}

describe("a hostile payload on every page", () => {
  // the scan page sets the tab title, and jsdom keeps it for the next test
  afterEach(() => {
    document.title = "";
  });

  it("the check below finds a raw character on the page", () => {
    // the gate's own positive control: a raw value in an attribute is reported
    document.body.innerHTML = `<p title="${HOSTILE}">ok</p>`;
    expect(rawCharactersOnPage()).toHaveLength(INJECTED.length);
    document.body.innerHTML = "";
  });

  it("the scan list", async () => {
    server.use(
      http.get("*/api/scans", () =>
        HttpResponse.json({ items: [hostile(makeScanSummary())], next_cursor: null }),
      ),
    );
    renderWithClient(<ScansPage />);
    await screen.findByRole("link", { name: /example\.com/ });
    expectNothingRaw();
  });

  it("the scan page, its technologies, filters and an open finding", async () => {
    const user = userEvent.setup();
    // a check id from a shared link that this scan has no finding for: the filter lists it with 0
    search.value = new URLSearchParams({ check_id: `cookies.flags${HOSTILE}` });
    const scan = makeScanOut({
      id: 7,
      status: "failed",
      mode: "active",
      authorized_by: "Security team",
      error: "the scan stopped",
      options: { max_pages: 50, disabled_checks: ["tls.version"] },
      technologies: [makeTechnology()],
    });
    const finding = makeFinding({
      location: {
        url: "https://example.com/",
        method: "GET",
        param: "q",
        header: null,
        cookie: null,
      },
      references: ["https://example.com/doc", "javascript:alert(1)"],
    });
    server.use(
      http.get("*/api/scans/7", () => HttpResponse.json(hostile(scan))),
      http.get("*/api/scans/7/findings", () =>
        HttpResponse.json({ items: [hostile(finding)], next_cursor: null, total: 1 }),
      ),
      http.get("*/api/scans/7/findings/checks", () =>
        HttpResponse.json(hostile([{ check_id: "headers.csp", count: 1 }])),
      ),
    );
    try {
      renderWithClient(<ScanDetailPage />);
      await user.click(await screen.findByRole("button", { name: /^Expand finding/ }));
      await screen.findByText(/Remediation\./);
      await waitFor(() => expect(document.title).toContain("example.com"));
      expectNothingRaw();
    } finally {
      search.value = new URLSearchParams();
    }
  });

  it("the checks page", async () => {
    server.use(
      http.get("*/api/checks", () =>
        HttpResponse.json(
          hostile([makeCheck({ references: ["https://owasp.org/", "javascript:alert(1)"] })]),
        ),
      ),
    );
    renderWithClient(<ChecksPage />);
    await screen.findByText(/^Content-Security-Policy/);
    expectNothingRaw();
  });

  it("the scan form, its check list and a 422 from the server", async () => {
    const user = userEvent.setup();
    server.use(
      http.get("*/api/config/defaults", () =>
        HttpResponse.json(
          hostile({
            mode: "passive",
            scope: "host",
            max_pages: 25,
            delay_ms: 300,
            follow_robots: true,
            fail_on: "medium",
          }),
        ),
      ),
      http.get("*/api/checks", () => HttpResponse.json(hostile([makeCheck()]))),
      http.post("*/api/scans", () =>
        HttpResponse.json(
          hostile({
            detail: [{ loc: ["body", "target"], msg: "unsupported", type: "value_error" }],
          }),
          { status: 422 },
        ),
      ),
    );
    renderWithClient(<ScanForm />);
    await screen.findByLabelText("Max pages");
    await user.click(screen.getByRole("button", { name: /disabled checks/i }));
    await screen.findByText(/^headers\.csp/);
    await user.type(screen.getByLabelText("Target"), "https://example.com");
    await user.click(screen.getByRole("button", { name: "Start scan" }));
    await screen.findByText(/^unsupported/);
    expectNothingRaw();
  });

  it("the report preview's error", async () => {
    const user = userEvent.setup();
    server.use(
      http.get("*/api/scans/9/report", () =>
        HttpResponse.json(hostile({ detail: "scan is still running" }), { status: 409 }),
      ),
    );
    renderWithClient(<ReportPreview scanId={9} disabled={false} />);
    await user.click(screen.getByRole("button", { name: /preview report/i }));
    await screen.findByText(/^scan is still running/);
    expectNothingRaw();
  });
});
