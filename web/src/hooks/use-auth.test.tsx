import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";

import { useLogout } from "@/hooks/use-auth";
import { server } from "@/test/msw/server";
import { makeTestClient, withClient } from "@/test/render";

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

describe("useLogout", () => {
  it("clears the query cache and returns to /login", async () => {
    server.use(http.post("*/api/auth/logout", () => new HttpResponse(null, { status: 204 })));
    const client = makeTestClient();
    client.setQueryData(["auth", "me"], { id: 1, username: "ana", created_at: "x" });

    const { result } = renderHook(() => useLogout(), { wrapper: withClient(client) });
    result.current.mutate();

    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/login"));
    expect(client.getQueryData(["auth", "me"])).toBeUndefined();
  });
});
