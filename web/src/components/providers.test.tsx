import { type QueryClient, useQuery, useQueryClient } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { useRef } from "react";
import { describe, expect, it, vi } from "vitest";

import { Providers, unauthorizedRedirect } from "@/components/providers";
import { useLogin } from "@/hooks/use-auth";
import { useCancelScan } from "@/hooks/use-scan";
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
      unauthorizedRedirect({ error: err401, hadSession: true, queryKey: keys.auth.me() }),
    ).toBeNull();
    expect(
      unauthorizedRedirect({ error: err401, hadSession: false, queryKey: keys.setup() }),
    ).toBeNull();
  });

  it("leaves a wrong password on the login attempt alone: it is not an expired session", () => {
    expect(
      unauthorizedRedirect({ error: err401, hadSession: false, queryKey: keys.auth.login() }),
    ).toBeNull();
  });
});

describe("Providers wiring", () => {
  /**
   * Asks the API once. The 401 handler wipes the cache, and the mocked router does not leave the
   * page, so a plain query would ask again for as long as it stays mounted (a real redirect
   * unmounts it); the later asks stay pending instead of reaching the next test.
   */
  function ScanProbe() {
    const asked = useRef(false);
    useQuery({
      queryKey: keys.scans.list(),
      queryFn: () => {
        if (asked.current) return new Promise<never>(() => {});
        asked.current = true;
        return api.listScans();
      },
      retry: false,
    });
    return <div>probe</div>;
  }

  /** Hands the test the provider's own client, which `Providers` creates and keeps inside. */
  function ClientProbe({ onClient }: { onClient: (client: QueryClient) => void }) {
    onClient(useQueryClient());
    return null;
  }

  /** A cache entry that is not the guard's, to see whether the 401 handler wiped the cache. */
  const MARKER = ["marker"] as const;

  it("redirects on a 401 from a normal query and wipes the cache", async () => {
    server.use(http.get("*/api/scans", () => HttpResponse.json({ detail: "no" }, { status: 401 })));
    let client: QueryClient | undefined;
    function Seed() {
      const queryClient = useQueryClient();
      queryClient.setQueryData(MARKER, "kept until the 401");
      return null;
    }
    render(
      <Providers>
        <Seed />
        <ClientProbe onClient={(c) => (client = c)} />
        <ScanProbe />
      </Providers>,
    );
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/login"));
    expect(client?.getQueryData(MARKER)).toBeUndefined();
  });

  it("tells a visitor whose session expired so, when the cache held the signed-in user", async () => {
    server.use(http.get("*/api/scans", () => HttpResponse.json({ detail: "no" }, { status: 401 })));
    function Seed() {
      useQueryClient().setQueryData(keys.auth.me(), { id: 1, username: "ana", created_at: "x" });
      return null;
    }
    render(
      <Providers>
        <Seed />
        <ScanProbe />
      </Providers>,
    );
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/login?reason=expired"));
  });

  it("redirects on a 401 from a mutation too", async () => {
    server.use(
      http.post("*/api/scans/3/cancel", () => HttpResponse.json({ detail: "no" }, { status: 401 })),
    );
    function CancelProbe() {
      const cancel = useCancelScan(3);
      return (
        <button type="button" onClick={() => cancel.mutate()}>
          cancel
        </button>
      );
    }
    const user = userEvent.setup();
    render(
      <Providers>
        <CancelProbe />
      </Providers>,
    );
    await user.click(screen.getByRole("button", { name: "cancel" }));
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/login"));
  });

  it("does not redirect, nor clear the cache, when the login attempt itself gets a 401", async () => {
    // a redirect to /login re-mounts the page: the form is hidden for a moment (the focus falls
    // to <body>) and the `?next=` it was going to return to is lost. The tests above are the
    // positive control: the same provider does redirect and wipe on any other 401.
    server.use(
      http.post("*/api/auth/login", () => HttpResponse.json({ detail: "no" }, { status: 401 })),
    );
    let client: QueryClient | undefined;
    function LoginProbe() {
      const login = useLogin();
      const queryClient = useQueryClient();
      return (
        <>
          <button
            type="button"
            onClick={() => {
              queryClient.setQueryData(MARKER, "still here");
              login.mutate({ username: "a", password: "b" });
            }}
          >
            go
          </button>
          {login.isError ? <p>login failed</p> : null}
        </>
      );
    }
    const user = userEvent.setup();
    render(
      <Providers>
        <ClientProbe onClient={(c) => (client = c)} />
        <LoginProbe />
      </Providers>,
    );
    await user.click(screen.getByRole("button", { name: "go" }));
    // the 401 has come back and gone through the provider's handler
    await screen.findByText("login failed");
    expect(router.replace).not.toHaveBeenCalled();
    expect(client?.getQueryData(MARKER)).toBe("still here");
  });
});
