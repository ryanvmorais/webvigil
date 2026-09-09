/** The scan list as a table — one row per scan, linking to its detail view (RF-11). */
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
import { absoluteTime, relativeTime } from "@/lib/format";
import type { ScanSummary } from "@/lib/api";

export function ScanListTable({ scans }: { scans: ScanSummary[] }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Target</TableHead>
          <TableHead>Mode</TableHead>
          <TableHead>Scope</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Findings</TableHead>
          <TableHead>Created</TableHead>
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
            <TableCell>
              <ModeBadge mode={scan.mode} />
            </TableCell>
            <TableCell className="text-muted-foreground capitalize">{scan.scope}</TableCell>
            <TableCell>
              <StatusBadge status={scan.status} />
            </TableCell>
            <TableCell>
              <SeveritySummary counts={scan.counts} />
            </TableCell>
            <TableCell className="text-muted-foreground" title={absoluteTime(scan.created_at)}>
              {relativeTime(scan.created_at)}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
