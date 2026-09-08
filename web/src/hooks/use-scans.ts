/**
 * Scan-list hooks: the cursor-paginated infinite query behind the list view, polled
 * while any loaded row is still running, and the create-scan mutation that redirects
 * to the new scan's detail page.
 */
"use client";

import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";

import { api, type ScanStatus } from "@/lib/api";
import { listInterval } from "@/lib/polling";
import { keys, type ScanListFilters } from "@/lib/query-keys";

/** Paginated scan list (RF-11), cursor-based (ADR-6), polled while anything runs (RF-13). */
export function useScanList(filters: ScanListFilters = {}) {
  return useInfiniteQuery({
    queryKey: keys.scans.list(filters),
    queryFn: ({ pageParam }) =>
      api.listScans({
        status: filters.status as ScanStatus | undefined,
        cursor: pageParam,
      }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    refetchInterval: (query) => {
      const statuses =
        query.state.data?.pages.flatMap((page) => page.items.map((item) => item.status)) ?? [];
      return listInterval(statuses);
    },
  });
}

/** `POST /api/scans` → the new scan's detail view (RF-18). */
export function useCreateScan() {
  const queryClient = useQueryClient();
  const router = useRouter();
  return useMutation({
    mutationFn: api.createScan,
    onSuccess: (scan) => {
      queryClient.invalidateQueries({ queryKey: keys.scans.all() });
      router.push(`/scans/${scan.id}`);
    },
  });
}
