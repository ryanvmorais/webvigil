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
  it("renders the form on the first render, with no Suspense fallback to swap out", () => {
    // a fallback replaced by the form after hydration shifts the card (CLS, issue #67)
    renderWithClient(<LoginPage />);
    expect(screen.getByLabelText("Username")).toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("returns the user to ?next after a successful login", async () => {
    // `useLogin` reads ?next= from the URL when the login succeeds, not from useSearchParams
    window.history.pushState({}, "", "/login?next=/scans/9");
    const user = userEvent.setup();
    server.use(http.post("*/api/auth/login", () => new HttpResponse(null, { status: 204 })));
    renderWithClient(<LoginPage />);
    await user.type(await screen.findByLabelText("Username"), "ana");
    await user.type(screen.getByLabelText("Password"), "supersecret");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/scans/9"));
    window.history.pushState({}, "", "/");
  });

  it.each(["https://evil.example", "//evil.example", "/\\evil.example"])(
    "goes to /scans after login when ?next is %s, not an in-app path",
    async (next) => {
      window.history.pushState({}, "", `/login?next=${encodeURIComponent(next)}`);
      const user = userEvent.setup();
      server.use(http.post("*/api/auth/login", () => new HttpResponse(null, { status: 204 })));
      renderWithClient(<LoginPage />);
      await user.type(await screen.findByLabelText("Username"), "ana");
      await user.type(screen.getByLabelText("Password"), "supersecret");
      await user.click(screen.getByRole("button", { name: "Sign in" }));
      await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/scans"));
      window.history.pushState({}, "", "/");
    },
  );

  it("keeps the focus on the button while the request runs, and sends it only once", async () => {
    // a `disabled` button hands the focus to <body>: after a wrong password a keyboard user
    // would have to Tab in from the top of the page
    const user = userEvent.setup();
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    const requests = vi.fn();
    server.use(
      http.post("*/api/auth/login", async () => {
        requests();
        await gate;
        return HttpResponse.json({ detail: "invalid username or password" }, { status: 401 });
      }),
    );
    renderWithClient(<LoginPage />);
    await user.type(await screen.findByLabelText("Username"), "ana");
    await user.type(screen.getByLabelText("Password"), "wrongpass");

    const button = screen.getByRole("button", { name: "Sign in" });
    await user.click(button);
    await waitFor(() => expect(button).toHaveAttribute("aria-disabled", "true"));
    await user.click(button);

    expect(button).not.toBeDisabled();
    expect(button).toHaveFocus();
    expect(requests).toHaveBeenCalledTimes(1);

    release();
    await screen.findByText("Invalid username or password.");
    expect(button).toHaveFocus();
    expect(button).not.toHaveAttribute("aria-disabled");
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
