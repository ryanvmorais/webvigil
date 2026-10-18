/**
 * The shared placeholders in `error-states.tsx`: the heading level of each (a page needs
 * exactly one `h1`, and a placeholder that fills the page has to supply it).
 *
 * Nothing is mocked; `next/link` renders as a plain anchor under jsdom.
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Empty, LoadFailed, NotFound } from "@/components/error-states";

describe("placeholder headings", () => {
  it("makes NotFound the page's h1, because it is the whole page", () => {
    render(<NotFound title="Scan not found" />);
    expect(screen.getByRole("heading", { level: 1, name: "Scan not found" })).toBeInTheDocument();
  });

  it("keeps Empty an h2, since it sits under a page that already has its h1", () => {
    render(<Empty title="No findings match this filter" />);
    expect(screen.getByRole("heading", { level: 2 })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { level: 1 })).not.toBeInTheDocument();
  });

  it("keeps LoadFailed an h2 unless the caller says it is the whole page", () => {
    const { rerender } = render(<LoadFailed />);
    expect(screen.getByRole("heading", { level: 2, name: "Something went wrong" })).toBeVisible();

    rerender(<LoadFailed heading="h1" />);
    expect(screen.getByRole("heading", { level: 1, name: "Something went wrong" })).toBeVisible();
  });
});
