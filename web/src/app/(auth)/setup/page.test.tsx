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
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    await fill(user);
    await user.click(screen.getByRole("button", { name: "Create account" }));
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/login?setup=done"));
    expect(body).toEqual({ username: "ana", password: "supersecret" });
  });

  it("blocks submission when the passwords do not match", async () => {
    // no handler for POST /api/setup: a request would fail the test (vitest.setup.ts)
    const user = userEvent.setup();
    renderWithClient(<SetupPage />);
    await fill(user, "supersecret", "different1");
    await user.click(screen.getByRole("button", { name: "Create account" }));
    expect(screen.getByText("Passwords do not match.")).toBeInTheDocument();
    expect(router.replace).not.toHaveBeenCalled();
  });

  it.each([
    ["", "an empty username"],
    ["a".repeat(65), "a username over 64 characters"],
  ])("blocks %#: %s", async (username) => {
    const user = userEvent.setup();
    renderWithClient(<SetupPage />);
    if (username) await user.type(screen.getByLabelText("Username"), username);
    await user.type(screen.getByLabelText("Password"), "supersecret");
    await user.type(screen.getByLabelText("Confirm password"), "supersecret");
    await user.click(screen.getByRole("button", { name: "Create account" }));
    expect(screen.getByText("1-64 characters.")).toBeInTheDocument();
  });

  it("blocks a 7-character password", async () => {
    const user = userEvent.setup();
    renderWithClient(<SetupPage />);
    await fill(user, "1234567");
    await user.click(screen.getByRole("button", { name: "Create account" }));
    expect(screen.getByText("At least 8 characters.")).toBeInTheDocument();
  });

  it("accepts a one-character username", async () => {
    const user = userEvent.setup();
    server.use(
      http.post("*/api/setup", () =>
        HttpResponse.json({ id: 1, username: "a", created_at: "x" }, { status: 201 }),
      ),
    );
    renderWithClient(<SetupPage />);
    await user.type(screen.getByLabelText("Username"), "a");
    await user.type(screen.getByLabelText("Password"), "supersecret");
    await user.type(screen.getByLabelText("Confirm password"), "supersecret");
    await user.click(screen.getByRole("button", { name: "Create account" }));
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/login?setup=done"));
  });

  it("accepts the limits themselves: a 64-character username and an 8-character password", async () => {
    const user = userEvent.setup();
    const posted = vi.fn();
    server.use(
      http.post("*/api/setup", () => {
        posted();
        return HttpResponse.json({ id: 1, username: "a", created_at: "x" }, { status: 201 });
      }),
    );
    renderWithClient(<SetupPage />);
    await user.type(screen.getByLabelText("Username"), "a".repeat(64));
    await user.type(screen.getByLabelText("Password"), "12345678");
    await user.type(screen.getByLabelText("Confirm password"), "12345678");
    await user.click(screen.getByRole("button", { name: "Create account" }));
    await waitFor(() => expect(posted).toHaveBeenCalledTimes(1));
    expect(screen.queryByText("1-64 characters.")).not.toBeInTheDocument();
    expect(screen.queryByText("At least 8 characters.")).not.toBeInTheDocument();
  });

  it("shows a generic error for a failure that names no field", async () => {
    const user = userEvent.setup();
    server.use(
      http.post("*/api/setup", () => HttpResponse.json({ detail: "boom" }, { status: 500 })),
    );
    renderWithClient(<SetupPage />);
    await fill(user);
    await user.click(screen.getByRole("button", { name: "Create account" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not create the account.");
    expect(screen.queryByText(/setup is already complete/i)).not.toBeInTheDocument();
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
    expect(screen.queryByText(/could not create the account/i)).not.toBeInTheDocument();
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
    expect(screen.queryByText(/could not create the account/i)).not.toBeInTheDocument();
  });
});
