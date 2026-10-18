/**
 * Tab titles (WCAG 2.4.2, page titled): the title each route segment sets in its server
 * `layout.tsx` through `pageTitle`, since the pages are Client Components and cannot export
 * `metadata`.
 *
 * Only the exported `metadata` objects are read; no layout is rendered. A route added later
 * without a layout keeps the fallback "WebVigil", which is what this list is meant to catch.
 * Nested routes are in the list on purpose: a first version used Next's `title.template`,
 * which did not reach `/scans/new` and `/scans/[id]`.
 */
import { describe, expect, it } from "vitest";

import { metadata as root } from "@/app/layout";
import { metadata as notFound } from "@/app/not-found";
import { metadata as checks } from "@/app/(app)/checks/layout";
import { metadata as scans } from "@/app/(app)/scans/layout";
import { metadata as scan } from "@/app/(app)/scans/[id]/layout";
import { metadata as newScan } from "@/app/(app)/scans/new/layout";
import { metadata as settings } from "@/app/(app)/settings/layout";
import { metadata as login } from "@/app/(auth)/login/layout";
import { metadata as setup } from "@/app/(auth)/setup/layout";
import { pageTitle } from "@/lib/page-title";

describe("pageTitle", () => {
  it("puts the page before the app name", () => {
    expect(pageTitle("Scans")).toBe("Scans | WebVigil");
  });
});

describe("tab titles", () => {
  it("falls back to the app name alone", () => {
    expect(root.title).toBe("WebVigil");
  });

  it.each([
    ["/scans", scans, "Scans | WebVigil"],
    ["/scans/new", newScan, "New scan | WebVigil"],
    ["/scans/[id]", scan, "Scan | WebVigil"],
    ["/checks", checks, "Checks | WebVigil"],
    ["/settings", settings, "Settings | WebVigil"],
    ["/login", login, "Sign in | WebVigil"],
    ["/setup", setup, "Create account | WebVigil"],
    ["a URL no route matches", notFound, "Page not found | WebVigil"],
  ])("titles %s", (_route, metadata, title) => {
    expect(metadata.title).toBe(title);
  });

  it("gives no two routes the same title", () => {
    const titles = [scans, newScan, scan, checks, settings, login, setup, notFound].map(
      (metadata) => metadata.title,
    );
    expect(new Set(titles).size).toBe(titles.length);
  });
});
