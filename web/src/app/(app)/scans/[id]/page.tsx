/**
 * `/scans/[id]` — the scan detail view (RF-20..RF-28): metadata, severity summary,
 * technology inventory, the filterable findings table, and the cancel / delete / report
 * actions. Polls the scan until it reaches a terminal status.
 */
"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useParams, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef } from "react";
import { toast } from "sonner";

import { ConfirmButton } from "@/components/confirm-button";
import { Empty, FullPageSpinner, LoadFailed, NotFound } from "@/components/error-states";
import { FindingsFilters } from "@/components/findings-filters";
import { FindingsTable } from "@/components/findings-table";
import { ModeBadge } from "@/components/mode-badge";
import { ReportMenu } from "@/components/report-menu";
import { ReportPreview } from "@/components/report-preview";
import { SeveritySummary } from "@/components/severity-summary";
import { StatusBadge } from "@/components/status-badge";
import { TechnologiesTable } from "@/components/technologies-table";
import { useFindings } from "@/hooks/use-findings";
import { useCancelScan, useDeleteScan, useScan } from "@/hooks/use-scan";
import { ApiError, REPORTABLE_STATUSES, TERMINAL_STATUSES, errorMessage } from "@/lib/api";
import { absoluteTime } from "@/lib/format";
import { keys } from "@/lib/query-keys";

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-muted-foreground text-xs tracking-wide uppercase">{label}</dt>
      <dd className="text-sm">{value}</dd>
    </div>
  );
}

function ScanDetail({ id }: { id: number }) {
  const queryClient = useQueryClient();
  const search = useSearchParams();
  const scan = useScan(id);
  const status = scan.data?.status;
  const isTerminal = status !== undefined && TERMINAL_STATUSES.has(status as never);

  const filters = {
    severity: search.get("severity") ?? undefined,
    checkId: search.get("check_id") ?? undefined,
  };
  const filtered = Boolean(filters.severity || filters.checkId);
  const findings = useFindings(id, filters);

  const cancel = useCancelScan(id);
  const remove = useDeleteScan(id);

  // Refetch the findings once, when the scan first reaches a terminal status (RF-21).
  const wasTerminal = useRef(false);
  useEffect(() => {
    if (isTerminal && !wasTerminal.current) {
      wasTerminal.current = true;
      queryClient.invalidateQueries({ queryKey: keys.scans.findings(id) });
    }
  }, [isTerminal, id, queryClient]);

  if (scan.isLoading) return <FullPageSpinner />;
  if (scan.error instanceof ApiError && scan.error.status === 404) {
    return <NotFound title="Scan not found" message="This scan does not exist." />;
  }
  if (scan.isError || !scan.data) {
    return <LoadFailed message="Could not load this scan." onRetry={() => scan.refetch()} />;
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

      <SeveritySummary counts={s.counts} />

      <dl className="grid gap-4 rounded-md border p-4 sm:grid-cols-3">
        <Row label="Scope" value={<span className="capitalize">{s.scope}</span>} />
        <Row label="Tool version" value={s.tool_version ?? "—"} />
        <Row label="Pages scanned" value={s.pages_scanned} />
        <Row label="Created" value={absoluteTime(s.created_at)} />
        <Row label="Started" value={absoluteTime(s.started_at)} />
        <Row label="Finished" value={absoluteTime(s.finished_at)} />
        {s.authorized_by ? <Row label="Authorized by" value={s.authorized_by} /> : null}
        <Row label="Options" value={<code className="text-xs">{JSON.stringify(s.options)}</code>} />
        {s.status === "failed" && s.error ? (
          <Row label="Error" value={<span className="text-destructive">{s.error}</span>} />
        ) : null}
      </dl>

      <TechnologiesTable items={s.technologies ?? []} />

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Findings</h2>
        <FindingsFilters />

        {findings.isLoading ? <FullPageSpinner /> : null}
        {findings.isError ? (
          <LoadFailed message="Could not load findings." onRetry={() => findings.refetch()} />
        ) : null}
        {findings.isSuccess && findings.data.length === 0 ? (
          <Empty
            title={filtered ? "No findings match this filter" : "This scan produced no findings"}
          />
        ) : null}
        {findings.data && findings.data.length > 0 ? (
          <div className="overflow-x-auto rounded-md border">
            <FindingsTable findings={findings.data} />
          </div>
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
