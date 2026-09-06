"use client";

import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";

import { LoadFailed, FullPageSpinner } from "@/components/error-states";
import { useMe, useSetupStatus } from "@/hooks/use-auth";
import { ApiError } from "@/lib/api";

function is401(error: unknown): boolean {
  return error instanceof ApiError && error.status === 401;
}

/**
 * Gates the `(app)` routes (RF-05, RF-08): ask `GET /api/setup`, then `GET /api/auth/me`,
 * redirecting to `/setup` or `/login?next=…` as needed. The 401 on `me` is expected here,
 * so the global handler leaves `["auth","me"]` to this component.
 */
export function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const setup = useSetupStatus();
  const needsSetup = setup.data?.needs_setup === true;
  const setupReady = setup.isSuccess;
  const me = useMe({ enabled: setupReady && !needsSetup });

  const unauthenticated = me.isError && is401(me.error);

  useEffect(() => {
    if (needsSetup) {
      router.replace("/setup");
    } else if (setupReady && unauthenticated) {
      router.replace(`/login?next=${encodeURIComponent(pathname)}`);
    }
  }, [needsSetup, setupReady, unauthenticated, pathname, router]);

  if (setup.isLoading) return <FullPageSpinner />;
  if (setup.isError) {
    return <LoadFailed message="Could not reach the API." onRetry={() => setup.refetch()} />;
  }
  if (needsSetup || me.isLoading || unauthenticated) return <FullPageSpinner />;
  if (me.isError) {
    return <LoadFailed message="Could not verify your session." onRetry={() => me.refetch()} />;
  }
  return <>{children}</>;
}
