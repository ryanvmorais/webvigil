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
  return http.get("*/api/setup", () => HttpResponse.json({ needs_setup: needsSetup }));
}

describe("AuthGuard", () => {
  it("redirects to /setup when the instance needs setup", async () => {
    server.use(mockSetup(true));
    renderWithClient(<AuthGuard>secret</AuthGuard>);
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/setup"));
  });

  it("redirects to /login with the requested path when unauthenticated", async () => {
    server.use(
      mockSetup(false),
      http.get("*/api/auth/me", () => HttpResponse.json({ detail: "no" }, { status: 401 })),
    );
    renderWithClient(<AuthGuard>secret</AuthGuard>);
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/login?next=%2Fscans%2F7"));
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
