"use client";

import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { keys } from "@/lib/query-keys";

/** `GET /api/config/defaults` — pre-fills the new-scan form (RF-15). */
export function useScanDefaults() {
  return useQuery({
    queryKey: keys.defaults(),
    queryFn: api.defaults,
    staleTime: 5 * 60_000,
  });
}
