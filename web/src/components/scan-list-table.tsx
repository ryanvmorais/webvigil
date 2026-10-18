/**
 * The scan list as a table — one row per scan, linking to its detail view (RF-11). Below the
 * `sm` breakpoint the Mode, Scope and Created columns are hidden (the detail view shows all
 * three), so Target, Status and Findings fit a phone without scrolling sideways.
 */
import Link from "next/link";

import { ModeBadge } from "@/components/mode-badge";
import { SeveritySummary } from "@/components/severity-summary";
import { StatusBadge } from "@/components/status-badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { TERMINAL_STATUSES } from "@/lib/api";
import { absoluteTime, relativeTime } from "@/lib/format";
import type { ScanSummary } from "@/lib/api";

const FROM_SM = "hidden sm:table-cell";

export function ScanListTable({ scans }: { scans: ScanSummary[] }) {
  return (
    <Table label="Scans" containerClassName="rounded-md border">
      <TableHeader>
        <TableRow>
          <TableHead>Target</TableHead>
          <TableHead className={FROM_SM}>Mode</TableHead>
          <TableHead className={FROM_SM}>Scope</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Findings</TableHead>
          <TableHead className={FROM_SM}>Created</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {scans.map((scan) => (
          <TableRow key={scan.id} className="[&_a]:no-underline">
            <TableCell className="font-medium">
              <Link href={`/scans/${scan.id}`} className="hover:underline">
                {scan.target}
              </Link>
            </TableCell>
            <TableCell className={FROM_SM}>
              <ModeBadge mode={scan.mode} />
            </TableCell>
            <TableCell className={`${FROM_SM} text-muted-foreground capitalize`}>
              {scan.scope}
            </TableCell>
            <TableCell>
              <StatusBadge status={scan.status} />
            </TableCell>
            <TableCell>
              <SeveritySummary
                counts={scan.counts}
                inProgress={!TERMINAL_STATUSES.has(scan.status as never)}
              />
            </TableCell>
            <TableCell
              className={`${FROM_SM} text-muted-foreground`}
              title={absoluteTime(scan.created_at)}
            >
              {relativeTime(scan.created_at)}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
