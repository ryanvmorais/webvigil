"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback } from "react";

/** Read the URL query and patch it (filters live in the URL — RF-12, RF-23). */
export function useQueryParams() {
  const router = useRouter();
  const pathname = usePathname();
  const search = useSearchParams();

  const setParams = useCallback(
    (updates: Record<string, string | null | undefined>) => {
      const next = new URLSearchParams(search.toString());
      for (const [key, value] of Object.entries(updates)) {
        if (value === null || value === undefined || value === "") next.delete(key);
        else next.set(key, value);
      }
      const qs = next.toString();
      router.replace(qs ? `${pathname}?${qs}` : pathname);
    },
    [router, pathname, search],
  );

  return { search, setParams };
}
