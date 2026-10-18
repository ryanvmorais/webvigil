/**
 * The 404 page for a URL no route matches: it must be a complete page (a `<main>`, one `h1`)
 * with a way back, not Next's bare default, which has no links and no landmark.
 *
 * Nothing is mocked.
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import NotFoundPage from "@/app/not-found";

describe("NotFoundPage", () => {
  it("is a page of its own: one main landmark and one h1", () => {
    render(<NotFoundPage />);
    expect(screen.getByRole("main")).toBeInTheDocument();
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Page not found");
  });

  it("links back to the scans", () => {
    render(<NotFoundPage />);
    expect(screen.getByRole("link", { name: "Back to scans" })).toHaveAttribute("href", "/scans");
  });
});
