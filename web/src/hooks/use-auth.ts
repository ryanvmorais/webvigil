/**
 * Auth and first-run-setup hooks — the queries behind the setup gate and the auth
 * guard, and the login / logout / setup / change-password mutations. Each wraps one
 * `/api/*` endpoint; the auth queries never retry so a 401 resolves immediately.
 */
"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";

import { api } from "@/lib/api";
import { keys } from "@/lib/query-keys";
import { safeNext } from "@/lib/safe-next";

/**
 * `GET /api/setup` — drives the setup gate (RF-05) and tells the `(auth)` layout whether
 * the visitor is already signed in (`authenticated`), so it never has to call
 * `/api/auth/me` and log a 401 in the console. Never retried.
 */
export function useSetupStatus() {
  return useQuery({
    queryKey: keys.setup(),
    queryFn: api.setupStatus,
    retry: false,
    staleTime: 0,
  });
}

/** `GET /api/auth/me` — drives the auth guard (RF-08). Never retried. */
export function useMe({ enabled = true }: { enabled?: boolean } = {}) {
  return useQuery({
    queryKey: keys.auth.me(),
    queryFn: api.me,
    retry: false,
    staleTime: 30_000,
    enabled,
  });
}

/** `GET /api/health` — the API version on the settings page (RF-30). */
export function useHealth() {
  return useQuery({ queryKey: keys.health(), queryFn: api.health });
}

/** `POST /api/setup` → `/login?setup=done` (RF-06). */
export function useSetup() {
  const router = useRouter();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.setup,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: keys.setup() });
      router.replace("/login?setup=done");
    },
  });
}

/**
 * `POST /api/auth/login` → the originally requested path, else `/scans` (RF-07, RF-08). Only
 * a same-origin path is honoured (`safeNext`): `?next=//host` must not leave the dashboard.
 *
 * `?next=` is read from `window.location` when the login succeeds, not through
 * `useSearchParams`: that hook forces a `<Suspense>` boundary around the login form, and
 * the boundary's fallback is what the page prerenders. Swapping it for the form after
 * hydration changes the card's height and shifts the layout (CLS).
 */
export function useLogin() {
  const queryClient = useQueryClient();
  const router = useRouter();
  return useMutation({
    mutationFn: api.login,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: keys.auth.me() });
      router.replace(safeNext(new URLSearchParams(window.location.search).get("next")));
    },
  });
}

/** `POST /api/auth/logout` → clear the cache → `/login` (RF-09). */
export function useLogout() {
  const queryClient = useQueryClient();
  const router = useRouter();
  return useMutation({
    mutationFn: api.logout,
    onSettled: () => {
      queryClient.clear();
      router.replace("/login");
    },
  });
}

/** `POST /api/auth/password` (RF-30). 403 (wrong current password) surfaces on the form. */
export function useChangePassword() {
  return useMutation({ mutationFn: api.changePassword });
}
