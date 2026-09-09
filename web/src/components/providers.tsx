/**
 * The app-wide TanStack Query provider plus its global error routing: a 401 on any query
 * or mutation sends the user to `/login` (unless the auth guard owns that probe).
 * `unauthorizedRedirect` is the pure decision function, unit-tested on its own.
 */
"use client";

import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { Toaster } from "@/components/ui/sonner";
import { ApiError } from "@/lib/api";
import { keys } from "@/lib/query-keys";

function ownedByGuard(queryKey?: readonly unknown[]): boolean {
  // The auth guard and the (auth) layout own the redirect for these probes (RF-05, RF-08).
  if (!Array.isArray(queryKey)) return false;
  return (queryKey[0] === "auth" && queryKey[1] === "me") || queryKey[0] === "setup";
}

/** Where a 401 should send the user, or `null` to leave it alone. Pure — unit-tested. */
export function unauthorizedRedirect(opts: {
  error: unknown;
  hadSession: boolean;
  queryKey?: readonly unknown[];
}): string | null {
  if (!(opts.error instanceof ApiError) || opts.error.status !== 401) return null;
  if (ownedByGuard(opts.queryKey)) return null;
  return opts.hadSession ? "/login?reason=expired" : "/login";
}

type ErrorHandler = (error: unknown, queryKey?: readonly unknown[]) => void;

export function Providers({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  // The cache callbacks call through this ref so the QueryClient can be created
  // once (below) while the handler still closes over the latest router.
  const handlerRef = useRef<ErrorHandler>(() => {});

  // The cache onError closures read `handlerRef.current`, but only when a query or
  // mutation actually errors — never during render — so the react-hooks/refs
  // warning here is a false positive for this "stable client, latest handler" pattern.
  /* eslint-disable react-hooks/refs */
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 5_000,
            refetchOnWindowFocus: false,
            retry: (failureCount, error) => !(error instanceof ApiError) && failureCount < 2,
          },
        },
        queryCache: new QueryCache({
          onError: (error, query) => handlerRef.current(error, query.queryKey),
        }),
        mutationCache: new MutationCache({
          onError: (error) => handlerRef.current(error),
        }),
      }),
  );
  /* eslint-enable react-hooks/refs */

  // Rebound every render so the handler always sees the current router/cache (RF-04, RF-10).
  useEffect(() => {
    handlerRef.current = (error, queryKey) => {
      const target = unauthorizedRedirect({
        error,
        queryKey,
        hadSession: client.getQueryData(keys.auth.me()) != null,
      });
      if (target === null) return;
      client.clear();
      router.replace(target);
    };
  });

  return (
    <QueryClientProvider client={client}>
      {children}
      <Toaster />
    </QueryClientProvider>
  );
}
