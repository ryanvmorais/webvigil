"use client";

import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";

import { FullPageSpinner } from "@/components/error-states";
import { useMe, useSetupStatus } from "@/hooks/use-auth";

/**
 * `/login` and `/setup` (RF-05, RF-08): send an authenticated user to `/scans`, route
 * to `/setup` while the instance needs setup, and away from `/setup` once it is done.
 */
export default function AuthLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const setup = useSetupStatus();
  const needsSetup = setup.data?.needs_setup === true;
  const me = useMe({ enabled: setup.isSuccess && !needsSetup });
  const authenticated = me.isSuccess;

  useEffect(() => {
    if (setup.isLoading) return;
    if (needsSetup && pathname !== "/setup") router.replace("/setup");
    else if (!needsSetup && pathname === "/setup") router.replace("/login");
    else if (!needsSetup && authenticated) router.replace("/scans");
  }, [needsSetup, authenticated, pathname, setup.isLoading, router]);

  const redirecting =
    (needsSetup && pathname !== "/setup") ||
    (!setup.isLoading && !needsSetup && pathname === "/setup") ||
    (!needsSetup && authenticated);

  return (
    <div className="grid min-h-screen place-items-center p-4">
      <div className="w-full max-w-sm">
        {setup.isLoading || redirecting ? <FullPageSpinner /> : children}
      </div>
    </div>
  );
}
