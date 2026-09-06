"use client";

import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { keys, type FindingFilters } from "@/lib/query-keys";

/** `GET /api/scans/{id}/findings` with the severity / check-id filters (RF-22, RF-23). */
export function useFindings(id: number, filters: FindingFilters = {}) {
  return useQuery({
    queryKey: keys.scans.findings(id, filters),
    queryFn: () => api.findings(id, { severity: filters.severity, check_id: filters.checkId }),
  });
}
