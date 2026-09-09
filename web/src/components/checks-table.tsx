/** The check catalogue as a sortable table (RF-29), filtered by the `category` / `mode` props. */
"use client";

import { ArrowDown, ArrowUp } from "lucide-react";
import { useMemo, useState } from "react";

import { SeverityBadge } from "@/components/severity-badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cweUrl } from "@/lib/format";
import { SEVERITY_NAMES } from "@/lib/severity";
import type { CheckOut } from "@/lib/api";

function severityRank(name: string): number {
  const index = (SEVERITY_NAMES as readonly string[]).indexOf(name);
  return index === -1 ? -1 : index;
}

export function ChecksTable({
  checks,
  category,
  mode,
}: {
  checks: CheckOut[];
  category: string;
  mode: string;
}) {
  const [sortDir, setSortDir] = useState<"asc" | "desc" | null>(null);

  const rows = useMemo(() => {
    let out = checks.filter(
      (check) =>
        (category === "all" || check.category === category) &&
        (mode === "all" || check.mode === mode),
    );
    if (sortDir) {
      out = [...out].sort((a, b) => {
        const diff = severityRank(a.default_severity) - severityRank(b.default_severity);
        return sortDir === "asc" ? diff : -diff;
      });
    }
    return out;
  }, [checks, category, mode, sortDir]);

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>ID</TableHead>
          <TableHead>Name</TableHead>
          <TableHead>Category</TableHead>
          <TableHead>Mode</TableHead>
          <TableHead>
            <button
              type="button"
              className="flex items-center gap-1"
              onClick={() =>
                setSortDir((prev) => (prev === "desc" ? "asc" : prev === "asc" ? null : "desc"))
              }
              aria-label={`Sort by default severity${sortDir ? ` (${sortDir}ending)` : ""}`}
            >
              Default severity
              {sortDir === "asc" ? <ArrowUp className="size-3" aria-hidden /> : null}
              {sortDir === "desc" ? <ArrowDown className="size-3" aria-hidden /> : null}
            </button>
          </TableHead>
          <TableHead>CWE</TableHead>
          <TableHead>References</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((check) => (
          <TableRow key={check.id}>
            <TableCell className="font-mono text-xs">{check.id}</TableCell>
            <TableCell className="font-medium">{check.name}</TableCell>
            <TableCell className="text-muted-foreground">{check.category}</TableCell>
            <TableCell className="text-muted-foreground capitalize">{check.mode}</TableCell>
            <TableCell>
              <SeverityBadge severity={check.default_severity} />
            </TableCell>
            <TableCell className="space-x-1">
              {check.cwe.length === 0 ? "—" : null}
              {check.cwe.map((id) => (
                <a
                  key={id}
                  href={cweUrl(id)}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="text-sm underline"
                >
                  CWE-{id}
                </a>
              ))}
            </TableCell>
            <TableCell className="space-y-1">
              {check.references.length === 0 ? "—" : null}
              {check.references.map((href) => (
                <a
                  key={href}
                  href={href}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="block max-w-xs truncate text-sm underline"
                >
                  {href}
                </a>
              ))}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
