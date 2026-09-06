import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";

import SettingsPage from "@/app/(app)/settings/page";
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

async function fillPasswords(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText("Current password"), "oldsecret");
  await user.type(screen.getByLabelText("New password"), "newsecret1");
  await user.type(screen.getByLabelText("Confirm new password"), "newsecret1");
}

describe("SettingsPage", () => {
  it("shows the API version", async () => {
    server.use(
      http.get("*/api/health", () => HttpResponse.json({ status: "ok", version: "0.3.0" })),
    );
    renderWithClient(<SettingsPage />);
    expect(await screen.findByText(/API version: 0\.3\.0/)).toBeInTheDocument();
  });

  it("reports a wrong current password on that field", async () => {
    const user = userEvent.setup();
    server.use(
      http.get("*/api/health", () => HttpResponse.json({ status: "ok", version: "0" })),
      http.post("*/api/auth/password", () =>
        HttpResponse.json({ detail: "current password is incorrect" }, { status: 403 }),
      ),
    );
    renderWithClient(<SettingsPage />);
    await fillPasswords(user);
    await user.click(screen.getByRole("button", { name: "Change password" }));
    expect(await screen.findByText("Current password is incorrect.")).toBeInTheDocument();
  });

  it("clears the form and confirms on success", async () => {
    const user = userEvent.setup();
    server.use(
      http.get("*/api/health", () => HttpResponse.json({ status: "ok", version: "0" })),
      http.post("*/api/auth/password", () => new HttpResponse(null, { status: 204 })),
    );
    renderWithClient(<SettingsPage />);
    await fillPasswords(user);
    await user.click(screen.getByRole("button", { name: "Change password" }));

    await screen.findByText("Password changed.");
    await waitFor(() => expect(screen.getByLabelText("Current password")).toHaveValue(""));
  });

  it("blocks a too-short new password before calling the API", async () => {
    const user = userEvent.setup();
    server.use(http.get("*/api/health", () => HttpResponse.json({ status: "ok", version: "0" })));
    renderWithClient(<SettingsPage />);
    await user.type(screen.getByLabelText("Current password"), "oldsecret");
    await user.type(screen.getByLabelText("New password"), "short");
    await user.type(screen.getByLabelText("Confirm new password"), "short");
    await user.click(screen.getByRole("button", { name: "Change password" }));
    expect(screen.getByText(/at least 8 characters/i)).toBeInTheDocument();
  });
});
