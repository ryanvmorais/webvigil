"use client";

import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";

import { FullPageSpinner } from "@/components/error-states";
import { useSetupStatus } from "@/hooks/use-auth";
import { cn } from "@/lib/utils";

/**
 * `/login` and `/setup` (RF-05, RF-08): send an authenticated user to `/scans`, route
 * to `/setup` while the instance needs setup, and away from `/setup` once it is done.
 *
 * One request decides all of it: `GET /api/setup` answers `needs_setup` and
 * `authenticated`. Asking `/api/auth/me` instead would log a 401 in the browser console
 * for every signed-out visitor (Lighthouse `errors-in-console`).
 *
 * The page is always rendered, hidden while the answer is pending or a redirect is on
 * its way, and the spinner sits over it. Swapping a spinner for the form would change
 * the card's height after the first paint, and the centred card would shift (CLS).
 *
 * "Pending" means no fetch has finished since this layout mounted, not just "no data":
 * after a login the cached status still says `authenticated: false`, and showing the
 * form from that stale answer would flash it at someone who is already signed in.
 */
export default function AuthLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const setup = useSetupStatus();
  const needsSetup = setup.data?.needs_setup === true;
  const authenticated = setup.data?.authenticated === true;
  const answered = setup.isFetchedAfterMount;

  useEffect(() => {
    if (!answered) return;
    if (needsSetup && pathname !== "/setup") router.replace("/setup");
    else if (!needsSetup && pathname === "/setup") router.replace("/login");
    else if (!needsSetup && authenticated) router.replace("/scans");
  }, [needsSetup, authenticated, pathname, answered, router]);

  const redirecting =
    (needsSetup && pathname !== "/setup") ||
    (answered && !needsSetup && pathname === "/setup") ||
    (!needsSetup && authenticated);
  const pending = !answered || redirecting;

  return (
    <div className="grid min-h-screen place-items-center p-4">
      <div className="relative w-full max-w-sm">
        <div className={cn(pending && "invisible")}>{children}</div>
        {pending ? <FullPageSpinner className="absolute inset-0 min-h-0" /> : null}
      </div>
    </div>
  );
}
