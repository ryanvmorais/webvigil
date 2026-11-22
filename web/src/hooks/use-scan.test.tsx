/**
 * The scan hooks: what the mutations mark stale, the retry rule of `useScan`, and the polling of a
 * running scan and of a list with a running row. The router is a stub, the API is MSW, and the
 * timers are fake where the interval matters.
 */
import { QueryClient } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useDeleteScan, useScan } from "@/hooks/use-scan";
import { useCreateScan, useScanList } from "@/hooks/use-scans";
import { DETAIL_POLL_MS, LIST_POLL_MS } from "@/lib/polling";
import { keys } from "@/lib/query-keys";
import { makeScanOut, makeScanSummary } from "@/test/fixtures";
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
  usePathname: () => "/scans",
  useSearchParams: () => new URLSearchParams(),
}));

afterEach(() => {
  vi.useRealTimers();
});

/**
 * A client whose cached list the mutations below should mark stale. It keeps unobserved data
 * (`makeTestClient` collects it at once), so the list is still there to be looked at.
 */
function clientWithList(): QueryClient {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(keys.scans.list(), { pages: [], pageParams: [] });
  return client;
}

describe("scan mutations", () => {
  it("deleting a scan marks the list stale and returns to it", async () => {
    server.use(http.delete("*/api/scans/7", () => new HttpResponse(null, { status: 204 })));
    const client = clientWithList();
    const { result } = renderHook(() => useDeleteScan(7), { wrapper: withClient(client) });

    act(() => result.current.mutate());
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/scans"));
    expect(client.getQueryState(keys.scans.list())?.isInvalidated).toBe(true);
  });

  it("creating a scan marks the list stale and opens the new scan", async () => {
    server.use(http.post("*/api/scans", () => HttpResponse.json({ id: 12 }, { status: 201 })));
    const client = clientWithList();
    const { result } = renderHook(() => useCreateScan(), { wrapper: withClient(client) });

    act(() =>
      result.current.mutate({
        target: "https://example.com",
        mode: "passive",
        scope: "host",
        disabled_checks: [],
      }),
    );
    await waitFor(() => expect(router.push).toHaveBeenCalledWith("/scans/12"));
    expect(client.getQueryState(keys.scans.list())?.isInvalidated).toBe(true);
  });
});

describe("useScan retry", () => {
  /** The test client turns retries off; this one keeps the hook's own rule, with no backoff. */
  const retryingClient = () =>
    new QueryClient({ defaultOptions: { queries: { retryDelay: 0, gcTime: 0 } } });

  it("retries a network failure twice", async () => {
    const calls = vi.fn();
    server.use(
      http.get("*/api/scans/7", () => {
        calls();
        return HttpResponse.error();
      }),
    );
    const { result } = renderHook(() => useScan(7), { wrapper: withClient(retryingClient()) });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(calls).toHaveBeenCalledTimes(3);
  });

  it("does not retry an answer from the API: a 404 stays a 404", async () => {
    const calls = vi.fn();
    server.use(
      http.get("*/api/scans/7", () => {
        calls();
        return HttpResponse.json({ detail: "scan not found" }, { status: 404 });
      }),
    );
    const { result } = renderHook(() => useScan(7), { wrapper: withClient(retryingClient()) });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(calls).toHaveBeenCalledTimes(1);
  });
});

describe("polling", () => {
  it("polls a running scan, and stops once it is terminal", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let status = "running";
    const calls = vi.fn();
    server.use(
      http.get("*/api/scans/7", () => {
        calls();
        return HttpResponse.json(makeScanOut({ id: 7, status }));
      }),
    );
    const { result } = renderHook(() => useScan(7), { wrapper: withClient(makeTestClient()) });
    await waitFor(() => expect(result.current.data?.status).toBe("running"));
    expect(calls).toHaveBeenCalledTimes(1);

    status = "completed";
    await act(() => vi.advanceTimersByTimeAsync(DETAIL_POLL_MS));
    await waitFor(() => expect(result.current.data?.status).toBe("completed"));
    expect(calls).toHaveBeenCalledTimes(2);

    await act(() => vi.advanceTimersByTimeAsync(DETAIL_POLL_MS * 3));
    expect(calls).toHaveBeenCalledTimes(2);
  });

  it("polls the list while a row is still running", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const calls = vi.fn();
    server.use(
      http.get("*/api/scans", () => {
        calls();
        return HttpResponse.json({
          items: [makeScanSummary({ status: "running" })],
          next_cursor: null,
        });
      }),
    );
    const { result } = renderHook(() => useScanList(), { wrapper: withClient(makeTestClient()) });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(calls).toHaveBeenCalledTimes(1);

    await act(() => vi.advanceTimersByTimeAsync(LIST_POLL_MS));
    await waitFor(() => expect(calls).toHaveBeenCalledTimes(2));
  });
});
