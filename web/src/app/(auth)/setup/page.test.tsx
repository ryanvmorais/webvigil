import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";

import SetupPage from "@/app/(auth)/setup/page";
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
  usePathname: () => "/setup",
  useSearchParams: () => new URLSearchParams(),
}));

async function fill(user: ReturnType<typeof userEvent.setup>, pw = "supersecret", confirm = pw) {
  await user.type(screen.getByLabelText("Username"), "ana");
  await user.type(screen.getByLabelText("Password"), pw);
  await user.type(screen.getByLabelText("Confirm password"), confirm);
}

describe("SetupPage", () => {
  it("posts and redirects to /login on success", async () => {
    const user = userEvent.setup();
    let body: unknown;
    server.use(
      http.post("*/api/setup", async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ id: 1, username: "ana", created_at: "x" }, { status: 201 });
      }),
    );
    renderWithClient(<SetupPage />);
    await fill(user);
    await user.click(screen.getByRole("button", { name: "Create account" }));
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/login?setup=done"));
    expect(body).toEqual({ username: "ana", password: "supersecret" });
  });

  it("blocks submission when the passwords do not match", async () => {
    const user = userEvent.setup();
    renderWithClient(<SetupPage />);
    await fill(user, "supersecret", "different1");
    await user.click(screen.getByRole("button", { name: "Create account" }));
    expect(screen.getByText("Passwords do not match.")).toBeInTheDocument();
    expect(router.replace).not.toHaveBeenCalled();
  });

  it("explains a 409 and links to sign in", async () => {
    const user = userEvent.setup();
    server.use(
      http.post("*/api/setup", () =>
        HttpResponse.json({ detail: "setup has already been completed" }, { status: 409 }),
      ),
    );
    renderWithClient(<SetupPage />);
    await fill(user);
    await user.click(screen.getByRole("button", { name: "Create account" }));
    await screen.findByText(/setup is already complete/i);
    expect(screen.getByRole("link", { name: /go to sign in/i })).toHaveAttribute("href", "/login");
  });

  it("shows field errors from a 422", async () => {
    const user = userEvent.setup();
    server.use(
      http.post("*/api/setup", () =>
        HttpResponse.json(
          { detail: [{ loc: ["body", "username"], msg: "already taken", type: "value_error" }] },
          { status: 422 },
        ),
      ),
    );
    renderWithClient(<SetupPage />);
    await fill(user);
    await user.click(screen.getByRole("button", { name: "Create account" }));
    await screen.findByText("already taken");
  });
});
