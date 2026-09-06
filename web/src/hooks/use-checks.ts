"use client";

import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { keys } from "@/lib/query-keys";

/** `GET /api/checks` — the catalogue (RF-29), reused by the scan form's disabled-checks control (RF-19). */
export function useChecks() {
  return useQuery({
    queryKey: keys.checks(),
    queryFn: api.checks,
    staleTime: 5 * 60_000,
  });
}
