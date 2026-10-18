import { useQuery } from "@tanstack/react-query";
import { render, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";

import { Providers, unauthorizedRedirect } from "@/components/providers";
import { useLogin } from "@/hooks/use-auth";
import { ApiError, api } from "@/lib/api";
import { keys } from "@/lib/query-keys";
import { server } from "@/test/msw/server";

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
  usePathname: () => "/scans",
  useSearchParams: () => new URLSearchParams(),
}));

describe("unauthorizedRedirect", () => {
  const err401 = new ApiError(401, "no");

  it("ignores non-401 and non-ApiError", () => {
    expect(unauthorizedRedirect({ error: new Error("x"), hadSession: false })).toBeNull();
    expect(unauthorizedRedirect({ error: new ApiError(500, "x"), hadSession: true })).toBeNull();
  });

  it("sends a fresh visitor to /login and an expired session to ?reason=expired", () => {
    expect(unauthorizedRedirect({ error: err401, hadSession: false })).toBe("/login");
    expect(unauthorizedRedirect({ error: err401, hadSession: true })).toBe("/login?reason=expired");
  });

  it("leaves the guard's own probes alone", () => {
    expect(
      unauthorizedRedirect({ error: err401, hadSession: true, queryKey: ["auth", "me"] }),
    ).toBeNull();
    expect(
      unauthorizedRedirect({ error: err401, hadSession: false, queryKey: ["setup"] }),
    ).toBeNull();
  });

  it("leaves a wrong password on the login attempt alone: it is not an expired session", () => {
    expect(
      unauthorizedRedirect({ error: err401, hadSession: false, queryKey: keys.auth.login() }),
    ).toBeNull();
  });
});

describe("Providers wiring", () => {
  function ScanProbe() {
    useQuery({ queryKey: keys.scans.list(), queryFn: () => api.listScans(), retry: false });
    return <div>probe</div>;
  }

  it("redirects on a 401 from a normal query", async () => {
    server.use(http.get("*/api/scans", () => HttpResponse.json({ detail: "no" }, { status: 401 })));
    render(
      <Providers>
        <ScanProbe />
      </Providers>,
    );
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/login"));
  });

  it("does not redirect, nor clear the cache, when the login attempt itself gets a 401", async () => {
    // a redirect to /login re-mounts the page: the form is hidden for a moment (the focus falls
    // to <body>) and the `?next=` it was going to return to is lost
    server.use(
      http.post("*/api/auth/login", () => HttpResponse.json({ detail: "no" }, { status: 401 })),
    );
    function LoginProbe() {
      const login = useLogin();
      return (
        <button type="button" onClick={() => login.mutate({ username: "a", password: "b" })}>
          go
        </button>
      );
    }
    const { getByRole } = render(
      <Providers>
        <LoginProbe />
      </Providers>,
    );
    getByRole("button", { name: "go" }).click();
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(router.replace).not.toHaveBeenCalled();
  });
});
