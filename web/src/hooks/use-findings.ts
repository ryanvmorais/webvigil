/**
 * Finding hooks for the scan detail view: the cursor-paginated findings (S-46: a hostile site can
 * make a scan produce thousands, so they come 50 at a time) and the per-check counts that fill the
 * Check filter.
 */
"use client";

import { keepPreviousData, useInfiniteQuery, useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { keys, type FindingFilters } from "@/lib/query-keys";

/**
 * `GET /api/scans/{id}/findings` with the severity / check-id / text filters (RF-22, RF-23),
 * one page per "Load more".
 *
 * @param id - The scan.
 * @param filters - The filters from the URL.
 * @returns The infinite query; `pages[n].total` counts every match.
 */
export function useFindings(id: number, filters: FindingFilters = {}) {
  return useInfiniteQuery({
    queryKey: keys.scans.findings(id, filters),
    queryFn: ({ pageParam }) =>
      api.findings(id, {
        severity: filters.severity,
        check_id: filters.checkId,
        q: filters.q,
        cursor: pageParam,
      }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    // Keep the rows on screen while a new search loads, instead of a spinner per keystroke.
    placeholderData: keepPreviousData,
  });
}

/**
 * `GET /api/scans/{id}/findings/checks`: the checks that found something, with their counts.
 *
 * @param id - The scan.
 * @returns The query.
 */
export function useFindingChecks(id: number) {
  return useQuery({
    queryKey: keys.scans.findingChecks(id),
    queryFn: () => api.findingChecks(id),
  });
}
