"use client";

import { ChevronRight } from "lucide-react";
import { Fragment, useState } from "react";

import { ConfidenceBadge } from "@/components/confidence-badge";
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
import { cn } from "@/lib/utils";
import type { FindingOut, LocationOut } from "@/lib/api";

function locationText(location: LocationOut): string {
  const qualifier = location.param
    ? `param ${location.param}`
    : location.header
      ? `header ${location.header}`
      : location.cookie
        ? `cookie ${location.cookie}`
        : null;
  return qualifier ? `${location.url} · ${qualifier}` : location.url;
}

/**
 * Findings in the exact order the API returns them — the UI never re-sorts (RNF-01).
 * A row expands to its full detail (RF-22).
 */
export function FindingsTable({ findings }: { findings: FindingOut[] }) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  function toggle(key: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-8" />
          <TableHead>Severity</TableHead>
          <TableHead>Title</TableHead>
          <TableHead>Check</TableHead>
          <TableHead>Location</TableHead>
          <TableHead>Confidence</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {findings.map((finding) => {
          const key = finding.fingerprint;
          const isOpen = expanded.has(key);
          return (
            <Fragment key={key}>
              <TableRow>
                <TableCell>
                  <button
                    type="button"
                    onClick={() => toggle(key)}
                    aria-expanded={isOpen}
                    aria-label={isOpen ? "Collapse finding" : "Expand finding"}
                  >
                    <ChevronRight
                      className={cn("size-4 transition-transform", isOpen && "rotate-90")}
                      aria-hidden
                    />
                  </button>
                </TableCell>
                <TableCell>
                  <SeverityBadge severity={finding.severity} />
                </TableCell>
                <TableCell className="font-medium">{finding.title}</TableCell>
                <TableCell className="font-mono text-xs">{finding.check_id}</TableCell>
                <TableCell className="max-w-xs truncate text-muted-foreground">
                  {locationText(finding.location)}
                </TableCell>
                <TableCell>
                  <ConfidenceBadge confidence={finding.confidence} />
                </TableCell>
              </TableRow>
              {isOpen ? (
                <TableRow>
                  <TableCell colSpan={6} className="bg-muted/40">
                    <div className="space-y-3 py-2 text-sm">
                      <p>{finding.description}</p>
                      <div>
                        <span className="font-semibold">Remediation. </span>
                        {finding.remediation}
                      </div>
                      {finding.evidence.map((item, index) => (
                        <div key={index}>
                          <div className="text-xs font-semibold text-muted-foreground">
                            {item.label}
                          </div>
                          <pre className="overflow-x-auto rounded bg-background p-2 text-xs">
                            {item.content}
                          </pre>
                        </div>
                      ))}
                      {finding.cwe.length > 0 ? (
                        <div className="space-x-2">
                          {finding.cwe.map((id) => (
                            <a
                              key={id}
                              href={cweUrl(id)}
                              target="_blank"
                              rel="noreferrer noopener"
                              className="underline"
                            >
                              CWE-{id}
                            </a>
                          ))}
                        </div>
                      ) : null}
                      {finding.references.length > 0 ? (
                        <ul className="list-inside list-disc">
                          {finding.references.map((href) => (
                            <li key={href}>
                              <a
                                href={href}
                                target="_blank"
                                rel="noreferrer noopener"
                                className="underline"
                              >
                                {href}
                              </a>
                            </li>
                          ))}
                        </ul>
                      ) : null}
                    </div>
                  </TableCell>
                </TableRow>
              ) : null}
            </Fragment>
          );
        })}
      </TableBody>
    </Table>
  );
}
