/**
 * `/scans` — the scan list (RF-11): status filter in the URL, cursor "load more", polled
 * while anything runs. Wrapped in `<Suspense>` because it reads `useSearchParams`.
 */
"use client";

import { Plus } from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { Empty, FullPageSpinner, LoadFailed } from "@/components/error-states";
import { ScanListTable } from "@/components/scan-list-table";
import { StatusFilter } from "@/components/status-filter";
import { Button } from "@/components/ui/button";
import { useScanList } from "@/hooks/use-scans";

function ScanList() {
  const search = useSearchParams();
  const status = search.get("status") ?? undefined;
  const query = useScanList({ status });

  const scans = query.data?.pages.flatMap((page) => page.items) ?? [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">Scans</h1>
        <Button asChild>
          <Link href="/scans/new">
            <Plus className="size-4" aria-hidden />
            New scan
          </Link>
        </Button>
      </div>

      <StatusFilter />

      {query.isLoading ? <FullPageSpinner /> : null}

      {query.isError ? (
        <LoadFailed message="Could not load scans." onRetry={() => query.refetch()} />
      ) : null}

      {query.isSuccess && scans.length === 0 ? (
        <Empty
          title={status ? "No scans with this status" : "No scans yet"}
          message={status ? undefined : "Run your first scan to see it here."}
          action={
            status ? undefined : (
              <Button asChild>
                <Link href="/scans/new">New scan</Link>
              </Button>
            )
          }
        />
      ) : null}

      {scans.length > 0 ? (
        <>
          <div className="overflow-x-auto rounded-md border">
            <ScanListTable scans={scans} />
          </div>
          {query.hasNextPage ? (
            <div className="flex justify-center">
              <Button
                variant="outline"
                onClick={() => query.fetchNextPage()}
                disabled={query.isFetchingNextPage}
              >
                {query.isFetchingNextPage ? "Loading…" : "Load more"}
              </Button>
            </div>
          ) : null}
        </>
      ) : null}
    </div>
  );
}

export default function ScansPage() {
  return (
    <Suspense fallback={<FullPageSpinner />}>
      <ScanList />
    </Suspense>
  );
}
