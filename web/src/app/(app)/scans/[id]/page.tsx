/**
 * `/scans/[id]` — the scan detail view (RF-20..RF-28): metadata, severity summary,
 * technology inventory, the filterable findings table, and the cancel / delete / report
 * actions. Polls the scan until it reaches a terminal status. Findings come 50 at a time,
 * with "Load more" as on the scan list (S-46).
 */
"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useParams, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef } from "react";
import { toast } from "sonner";

import { ConfirmButton } from "@/components/confirm-button";
import { Button } from "@/components/ui/button";
import { Empty, FullPageSpinner, LoadFailed, NotFound } from "@/components/error-states";
import { FindingsFilters } from "@/components/findings-filters";
import { FindingsTable } from "@/components/findings-table";
import { ModeBadge } from "@/components/mode-badge";
import { ReportMenu } from "@/components/report-menu";
import { ReportPreview } from "@/components/report-preview";
import { SeveritySummary } from "@/components/severity-summary";
import { StatusBadge } from "@/components/status-badge";
import { TechnologiesTable } from "@/components/technologies-table";
import { useDocumentTitle } from "@/hooks/use-document-title";
import { useFindings } from "@/hooks/use-findings";
import { useCancelScan, useDeleteScan, useScan } from "@/hooks/use-scan";
import { ApiError, REPORTABLE_STATUSES, TERMINAL_STATUSES, errorMessage } from "@/lib/api";
import { absoluteTime, optionsText } from "@/lib/format";
import { pageTitle } from "@/lib/page-title";
import { keys } from "@/lib/query-keys";

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-muted-foreground text-xs tracking-wide uppercase">{label}</dt>
      <dd className="text-sm">{value}</dd>
    </div>
  );
}

/** A scan still running has not finished looking, so an empty list must not read as "clean". */
function emptyFindingsTitle(filtered: boolean, isTerminal: boolean): string {
  if (filtered) return "No findings match this filter";
  return isTerminal
    ? "This scan produced no findings"
    : "Findings will appear here as the scan runs";
}

/** "50 of 1,234 findings shown", or "All 12 findings shown" once every page is in. */
function countText(shown: number, total: number): string {
  const format = (value: number) => value.toLocaleString("en-US");
  if (shown >= total) return `All ${format(total)} ${total === 1 ? "finding" : "findings"} shown`;
  return `${format(shown)} of ${format(total)} findings shown`;
}

function ScanDetail({ id }: { id: number }) {
  const queryClient = useQueryClient();
  const search = useSearchParams();
  const scan = useScan(id);
  const status = scan.data?.status;
  const isTerminal = status !== undefined && TERMINAL_STATUSES.has(status as never);

  // The route layout titles the tab "Scan"; the target is only known once the scan loads.
  const isMissing = scan.error instanceof ApiError && scan.error.status === 404;
  useDocumentTitle(
    scan.data ? pageTitle(scan.data.target) : isMissing ? pageTitle("Scan not found") : undefined,
  );

  const filters = {
    severity: search.get("severity") ?? undefined,
    checkId: search.get("check_id") ?? undefined,
    q: search.get("q") ?? undefined,
  };
  const filtered = Boolean(filters.severity || filters.checkId || filters.q);
  const findings = useFindings(id, filters);
  const items = findings.data?.pages.flatMap((page) => page.items) ?? [];
  const total = findings.data?.pages.at(-1)?.total ?? 0;

  const cancel = useCancelScan(id);
  const remove = useDeleteScan(id);

  // Refetch the findings once, when the scan first reaches a terminal status (RF-21).
  const wasTerminal = useRef(false);
  useEffect(() => {
    if (isTerminal && !wasTerminal.current) {
      wasTerminal.current = true;
      queryClient.invalidateQueries({ queryKey: keys.scans.findings(id) });
      queryClient.invalidateQueries({ queryKey: keys.scans.findingChecks(id) });
    }
  }, [isTerminal, id, queryClient]);

  if (scan.isLoading) return <FullPageSpinner />;
  if (isMissing) {
    return <NotFound title="Scan not found" message="This scan does not exist." />;
  }
  if (scan.isError || !scan.data) {
    return (
      <LoadFailed message="Could not load this scan." onRetry={() => scan.refetch()} heading="h1" />
    );
  }

  const s = scan.data;

  function onCancel() {
    cancel.mutate(undefined, {
      onError: (error) => {
        toast.error(errorMessage(error, "Could not cancel the scan."));
      },
    });
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <h1 className="text-xl font-semibold">{s.target}</h1>
          <div className="flex items-center gap-2" aria-live="polite">
            <StatusBadge status={s.status} />
            <ModeBadge mode={s.mode} />
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <ReportPreview scanId={id} disabled={!REPORTABLE_STATUSES.has(s.status as never)} />
          <ReportMenu scanId={id} status={s.status} />
          {!isTerminal ? (
            <ConfirmButton
              label="Cancel"
              title="Cancel this scan?"
              description="The scan stops immediately and keeps no partial findings."
              confirmLabel="Cancel scan"
              variant="outline"
              pending={cancel.isPending}
              onConfirm={onCancel}
            />
          ) : null}
          <ConfirmButton
            label="Delete"
            title="Delete this scan?"
            description="The scan and its findings are removed permanently."
            confirmLabel="Delete scan"
            variant="destructive"
            disabled={!isTerminal}
            pending={remove.isPending}
            onConfirm={() => remove.mutate()}
          />
        </div>
      </div>

      <SeveritySummary counts={s.counts} inProgress={!isTerminal} />

      <dl className="grid gap-4 rounded-md border p-4 sm:grid-cols-3">
        <Row label="Scope" value={<span className="capitalize">{s.scope}</span>} />
        <Row label="Tool version" value={s.tool_version ?? "—"} />
        <Row label="Pages scanned" value={s.pages_scanned} />
        <Row label="Created" value={absoluteTime(s.created_at)} />
        <Row label="Started" value={absoluteTime(s.started_at)} />
        <Row label="Finished" value={absoluteTime(s.finished_at)} />
        {s.authorized_by ? <Row label="Authorized by" value={s.authorized_by} /> : null}
        <Row label="Options" value={optionsText(s.options)} />
        {s.status === "failed" && s.error ? (
          <Row label="Error" value={<span className="text-destructive">{s.error}</span>} />
        ) : null}
      </dl>

      <TechnologiesTable items={s.technologies ?? []} />

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Findings</h2>
        <FindingsFilters scanId={id} />

        {findings.isLoading ? <FullPageSpinner /> : null}
        {findings.isError ? (
          <LoadFailed message="Could not load findings." onRetry={() => findings.refetch()} />
        ) : null}
        {findings.isSuccess && items.length === 0 ? (
          <Empty title={emptyFindingsTitle(filtered, isTerminal)} />
        ) : null}
        {items.length > 0 ? (
          <>
            <FindingsTable findings={items} />
            <div className="flex flex-col items-center gap-1.5">
              {findings.hasNextPage ? (
                <Button
                  variant="outline"
                  onClick={() => findings.fetchNextPage()}
                  disabled={findings.isFetchingNextPage}
                >
                  {findings.isFetchingNextPage ? "Loading…" : "Load more"}
                </Button>
              ) : null}
              <p className="text-muted-foreground text-sm tabular-nums" aria-live="polite">
                {countText(items.length, total)}
              </p>
            </div>
          </>
        ) : null}
      </section>
    </div>
  );
}

export default function ScanDetailPage() {
  const params = useParams<{ id: string }>();
  const id = Number(params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return <NotFound title="Scan not found" message="That is not a valid scan id." />;
  }
  return (
    <Suspense fallback={<FullPageSpinner />}>
      <ScanDetail id={id} />
    </Suspense>
  );
}
