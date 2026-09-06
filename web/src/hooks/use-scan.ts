"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";

import { api, ApiError } from "@/lib/api";
import { detailInterval } from "@/lib/polling";
import { keys } from "@/lib/query-keys";

/** One scan, polled until terminal (RF-20, RF-21). A 404 is not retried. */
export function useScan(id: number) {
  return useQuery({
    queryKey: keys.scans.detail(id),
    queryFn: () => api.getScan(id),
    retry: (failureCount, error) => !(error instanceof ApiError) && failureCount < 2,
    refetchInterval: (query) => detailInterval(query.state.data?.status),
  });
}

/** `POST /api/scans/{id}/cancel` (RF-25). */
export function useCancelScan(id: number) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.cancelScan(id),
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: keys.scans.detail(id) });
      queryClient.invalidateQueries({ queryKey: keys.scans.all() });
    },
  });
}

/** `DELETE /api/scans/{id}` → back to the list (RF-26). */
export function useDeleteScan(id: number) {
  const queryClient = useQueryClient();
  const router = useRouter();
  return useMutation({
    mutationFn: () => api.deleteScan(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: keys.scans.all() });
      router.replace("/scans");
    },
  });
}
