"use client";

import { Download } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { REPORTABLE_STATUSES, REPORT_FORMATS, api } from "@/lib/api";

/** Download the report in any of the four formats (RF-27). Disabled until the scan can report. */
export function ReportMenu({ scanId, status }: { scanId: number; status: string }) {
  const enabled = REPORTABLE_STATUSES.has(status as never);

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          disabled={!enabled}
          title={enabled ? undefined : "Available once the scan completes"}
        >
          <Download className="size-4" aria-hidden />
          Report
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {REPORT_FORMATS.map((format) => (
          <DropdownMenuItem key={format} asChild>
            <a href={api.reportUrl(scanId, format, true)} download>
              {format.toUpperCase()}
            </a>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
