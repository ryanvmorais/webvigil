/**
 * `next/navigation` test double. `mockNavigation()` installs router/pathname/search
 * spies and turns `redirect()` / `notFound()` into throwable {@link RedirectError} /
 * {@link NotFoundError}, so a test can assert the navigation a component triggers.
 */
import { vi } from "vitest";

export class RedirectError extends Error {
  constructor(readonly url: string) {
    super(`redirect:${url}`);
  }
}

export class NotFoundError extends Error {
  constructor() {
    super("not-found");
  }
}

/**
 * Mock `next/navigation` for a test. Call BEFORE `await import()`-ing the component under
 * test (uses `vi.doMock`, which is not hoisted). Returns the spies to assert on.
 */
export function mockNavigation(opts?: { pathname?: string; searchParams?: string }) {
  const router = {
    push: vi.fn(),
    replace: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
    refresh: vi.fn(),
    prefetch: vi.fn(),
  };
  const state = {
    pathname: opts?.pathname ?? "/scans",
    search: new URLSearchParams(opts?.searchParams ?? ""),
  };

  vi.doMock("next/navigation", () => ({
    useRouter: () => router,
    usePathname: () => state.pathname,
    useSearchParams: () => state.search,
    redirect: (url: string) => {
      throw new RedirectError(url);
    },
    notFound: () => {
      throw new NotFoundError();
    },
  }));

  return { router, state };
}
