"use client";

import { ShieldAlert } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useQueryParams } from "@/hooks/use-query-param";
import type { TechnologyOut } from "@/lib/api";

const VULNERABLE_CHECK_ID = "deps.js.vulnerable-library";

function vulnerableLabel(advisories: number): string {
  if (advisories === 0) return "Vulnerable";
  return `Vulnerable · ${advisories} ${advisories === 1 ? "advisory" : "advisories"}`;
}

/**
 * The detected client-side stack for a scan (spec 004, RF-18). Rendered from
 * `ScanOut.technologies`; hidden when the scan detected nothing. A vulnerable row links to
 * the matching findings in the same view.
 */
export function TechnologiesTable({ items }: { items: TechnologyOut[] }) {
  const { setParams } = useQueryParams();

  if (items.length === 0) return null;

  return (
    <section className="space-y-3">
      <h2 className="text-lg font-semibold">Detected technologies</h2>
      <Table label="Detected technologies" containerClassName="rounded-md border">
        <TableHeader>
          <TableRow>
            <TableHead>Library</TableHead>
            <TableHead>Version</TableHead>
            <TableHead>Detection</TableHead>
            <TableHead>Status</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map((tech) => (
            <TableRow key={`${tech.name}@${tech.version ?? "?"}`}>
              <TableCell className="font-medium">{tech.name}</TableCell>
              <TableCell>{tech.version ?? "unknown"}</TableCell>
              <TableCell className="text-muted-foreground">{tech.detection}</TableCell>
              <TableCell>
                {tech.vulnerable ? (
                  <button
                    type="button"
                    onClick={() => setParams({ check_id: VULNERABLE_CHECK_ID })}
                    title={tech.advisories.length > 0 ? tech.advisories.join(", ") : undefined}
                    className="rounded-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2"
                  >
                    {/* The advisory ids (up to a dozen) go in the tooltip and in the finding
                        this button filters to; inside the badge they made a 12-line column. */}
                    <Badge variant="outline" className="text-severity-critical gap-1">
                      <ShieldAlert className="size-3" aria-hidden />
                      {vulnerableLabel(tech.advisories.length)}
                      <span className="sr-only">: show findings for vulnerable libraries</span>
                    </Badge>
                  </button>
                ) : (
                  <span className="text-muted-foreground">—</span>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </section>
  );
}
