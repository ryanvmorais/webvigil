import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";

import LoginPage from "@/app/(auth)/login/page";
import { server } from "@/test/msw/server";
import { renderWithClient } from "@/test/render";

const { router, searchParams } = vi.hoisted(() => ({
  router: {
    replace: vi.fn(),
    push: vi.fn(),
    prefetch: vi.fn(),
    refresh: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
  },
  searchParams: new URLSearchParams(),
}));
vi.mock("next/navigation", () => ({
  useRouter: () => router,
  usePathname: () => "/login",
  useSearchParams: () => searchParams,
}));

describe("LoginPage", () => {
  it("returns the user to ?next after a successful login", async () => {
    const user = userEvent.setup();
    searchParams.set("next", "/scans/9");
    server.use(http.post("*/api/auth/login", () => new HttpResponse(null, { status: 204 })));
    renderWithClient(<LoginPage />);
    await user.type(await screen.findByLabelText("Username"), "ana");
    await user.type(screen.getByLabelText("Password"), "supersecret");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/scans/9"));
    searchParams.delete("next");
  });

  it("shows one generic error, clears the password, keeps the username on 401", async () => {
    const user = userEvent.setup();
    server.use(
      http.post("*/api/auth/login", () =>
        HttpResponse.json({ detail: "invalid username or password" }, { status: 401 }),
      ),
    );
    renderWithClient(<LoginPage />);
    await user.type(await screen.findByLabelText("Username"), "ana");
    await user.type(screen.getByLabelText("Password"), "wrongpass");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    await screen.findByText("Invalid username or password.");
    expect(screen.getByLabelText("Username")).toHaveValue("ana");
    expect(screen.getByLabelText("Password")).toHaveValue("");
    expect(router.replace).not.toHaveBeenCalled();
  });

  it("renders the expired-session notice", async () => {
    searchParams.set("reason", "expired");
    renderWithClient(<LoginPage />);
    expect(await screen.findByText(/your session expired/i)).toBeInTheDocument();
    searchParams.delete("reason");
  });
});
