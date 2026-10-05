/**
 * The `(auth)` layout (RF-05, RF-08): one `GET /api/setup` decides whether to show the
 * page, send the visitor to `/setup`, or send a signed-in one to `/scans`.
 *
 * Isolation: `next/navigation` is mocked (a router spy and a mutable pathname) and the
 * API is faked with MSW. Two things are pinned on purpose. The layout never calls
 * `/api/auth/me` (a 401 there is a console error on `/login`, Lighthouse
 * `errors-in-console`), and the page stays in the DOM, only hidden, while the answer is
 * pending (swapping a spinner for the form shifts the card, CLS).
 */
import { screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it, vi } from "vitest";

import AuthLayout from "@/app/(auth)/layout";
import { keys } from "@/lib/query-keys";
import { server } from "@/test/msw/server";
import { makeTestClient, renderWithClient } from "@/test/render";

const { router, nav } = vi.hoisted(() => ({
  router: {
    replace: vi.fn(),
    push: vi.fn(),
    prefetch: vi.fn(),
    refresh: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
  },
  nav: { pathname: "/login" },
}));

vi.mock("next/navigation", () => ({
  useRouter: () => router,
  usePathname: () => nav.pathname,
  useSearchParams: () => new URLSearchParams(),
}));

type Status = { needs_setup: boolean; authenticated: boolean };

function mockSetup(status: Status) {
  return http.get("*/api/setup", () => HttpResponse.json(status));
}

/** Fails the test run if the layout asks who the visitor is the old way. */
function spyOnMe() {
  const calls = vi.fn();
  const handler = http.get("*/api/auth/me", () => {
    calls();
    return HttpResponse.json({ detail: "not authenticated" }, { status: 401 });
  });
  return { calls, handler };
}

function renderLayout(client = makeTestClient()) {
  return renderWithClient(
    <AuthLayout>
      <p>the page</p>
    </AuthLayout>,
    client,
  );
}

/** The wrapper `AuthLayout` puts around its children, which carries `invisible`. */
function pageWrapper() {
  return screen.getByText("the page").parentElement as HTMLElement;
}

beforeEach(() => {
  nav.pathname = "/login";
});

describe("AuthLayout", () => {
  it("keeps the page in the DOM, hidden under a spinner, until /api/setup answers", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    server.use(
      http.get("*/api/setup", async () => {
        await gate;
        return HttpResponse.json({ needs_setup: false, authenticated: false });
      }),
    );
    renderLayout();

    expect(pageWrapper()).toHaveClass("invisible");
    expect(screen.getByRole("status")).toBeInTheDocument();

    release();
    await waitFor(() => expect(pageWrapper()).not.toHaveClass("invisible"));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("shows the page to a signed-out visitor without asking /api/auth/me", async () => {
    const me = spyOnMe();
    server.use(mockSetup({ needs_setup: false, authenticated: false }), me.handler);
    renderLayout();

    await waitFor(() => expect(pageWrapper()).not.toHaveClass("invisible"));
    expect(me.calls).not.toHaveBeenCalled();
    expect(router.replace).not.toHaveBeenCalled();
  });

  it("sends a signed-in visitor to /scans, again without asking /api/auth/me", async () => {
    const me = spyOnMe();
    server.use(mockSetup({ needs_setup: false, authenticated: true }), me.handler);
    renderLayout();

    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/scans"));
    expect(me.calls).not.toHaveBeenCalled();
    expect(pageWrapper()).toHaveClass("invisible");
  });

  it("does not show the page from a stale cached answer", async () => {
    const client = makeTestClient();
    client.setQueryData(keys.setup(), { needs_setup: false, authenticated: false });
    server.use(mockSetup({ needs_setup: false, authenticated: true }));
    renderLayout(client);

    // the cache says "signed out", but the cookie has been set since: hide until refetched
    expect(pageWrapper()).toHaveClass("invisible");
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/scans"));
  });

  it("sends the visitor from /login to /setup while the instance needs setup", async () => {
    server.use(mockSetup({ needs_setup: true, authenticated: false }));
    renderLayout();

    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/setup"));
    expect(pageWrapper()).toHaveClass("invisible");
  });

  it("keeps the visitor on /setup while the instance needs setup", async () => {
    nav.pathname = "/setup";
    server.use(mockSetup({ needs_setup: true, authenticated: false }));
    renderLayout();

    await waitFor(() => expect(pageWrapper()).not.toHaveClass("invisible"));
    expect(router.replace).not.toHaveBeenCalled();
  });

  it("sends the visitor from /setup to /login once setup is done", async () => {
    nav.pathname = "/setup";
    server.use(mockSetup({ needs_setup: false, authenticated: false }));
    renderLayout();

    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/login"));
    expect(pageWrapper()).toHaveClass("invisible");
  });

  it("shows the page when the API cannot be reached, instead of an endless spinner", async () => {
    server.use(http.get("*/api/setup", () => HttpResponse.error()));
    renderLayout();

    await waitFor(() => expect(pageWrapper()).not.toHaveClass("invisible"));
    expect(router.replace).not.toHaveBeenCalled();
  });
});
