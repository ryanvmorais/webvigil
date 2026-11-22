/**
 * `LogoutButton`: the session ends on the API before the page leaves. The router is a stub, the
 * API is MSW.
 */
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";

import { LogoutButton } from "@/components/logout-button";
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
  usePathname: () => "/settings",
  useSearchParams: () => new URLSearchParams(),
}));

describe("LogoutButton", () => {
  it("ends the session on the API before it leaves", async () => {
    const user = userEvent.setup();
    const ended = vi.fn();
    server.use(
      http.post("*/api/auth/logout", () => {
        ended();
        return new HttpResponse(null, { status: 204 });
      }),
    );
    renderWithClient(<LogoutButton />);
    await user.click(screen.getByRole("button", { name: "Log out" }));
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/login"));
    expect(ended).toHaveBeenCalledTimes(1);
  });
});
