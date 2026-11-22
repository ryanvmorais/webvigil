import { screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";

import { AuthGuard } from "@/components/auth-guard";
import { server } from "@/test/msw/server";
import { renderWithClient } from "@/test/render";

const { router } = vi.hoisted(() => ({
  router: {
    replace: vi.fn(),
    push: vi.fn(),
    prefetch: vi.fn(),
    refresh: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
  },
}));

vi.mock("next/navigation", () => ({
  useRouter: () => router,
  usePathname: () => "/scans/7",
  useSearchParams: () => new URLSearchParams(),
}));

const user = { id: 1, username: "ana", created_at: "2026-01-01T00:00:00Z" };

function mockSetup(needsSetup: boolean) {
  return http.get("*/api/setup", () =>
    HttpResponse.json({ needs_setup: needsSetup, authenticated: false }),
  );
}

describe("AuthGuard", () => {
  it("redirects to /setup when the instance needs setup, without asking who is signed in", async () => {
    // no handler for /api/auth/me: asking it would fail the test (vitest.setup.ts)
    server.use(mockSetup(true));
    renderWithClient(<AuthGuard>secret</AuthGuard>);
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/setup"));
    expect(screen.queryByText("secret")).not.toBeInTheDocument();
  });

  it("redirects to /login with the requested path when unauthenticated", async () => {
    server.use(
      mockSetup(false),
      http.get("*/api/auth/me", () => HttpResponse.json({ detail: "no" }, { status: 401 })),
    );
    renderWithClient(<AuthGuard>secret</AuthGuard>);
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/login?next=%2Fscans%2F7"));
    expect(screen.queryByText("secret")).not.toBeInTheDocument();
    // a spinner until the redirect lands: a 401 is expected here, not a failure to report
    expect(screen.queryByText("Could not verify your session.")).not.toBeInTheDocument();
  });

  it("keeps the page hidden until the session check answers", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    const asked = vi.fn();
    server.use(
      mockSetup(false),
      http.get("*/api/auth/me", async () => {
        asked();
        await gate;
        return HttpResponse.json(user);
      }),
    );
    renderWithClient(<AuthGuard>secret content</AuthGuard>);
    await waitFor(() => expect(asked).toHaveBeenCalledTimes(1));
    expect(screen.queryByText("secret content")).not.toBeInTheDocument();
    release();
    await screen.findByText("secret content");
  });

  it("shows a retry state, not the sign-in page, when the session check fails otherwise", async () => {
    server.use(
      mockSetup(false),
      http.get("*/api/auth/me", () => HttpResponse.json({ detail: "boom" }, { status: 500 })),
    );
    renderWithClient(<AuthGuard>secret</AuthGuard>);
    await screen.findByText("Could not verify your session.");
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
    expect(router.replace).not.toHaveBeenCalled();
    expect(screen.queryByText("secret")).not.toBeInTheDocument();
  });

  it("renders children for a valid session", async () => {
    server.use(
      mockSetup(false),
      http.get("*/api/auth/me", () => HttpResponse.json(user)),
    );
    renderWithClient(<AuthGuard>secret content</AuthGuard>);
    await screen.findByText("secret content");
    expect(router.replace).not.toHaveBeenCalled();
  });

  it("shows a retry state when the setup probe fails hard", async () => {
    server.use(http.get("*/api/setup", () => HttpResponse.error()));
    renderWithClient(<AuthGuard>secret</AuthGuard>);
    await screen.findByText(/could not reach the api/i);
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });
});
