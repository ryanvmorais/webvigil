"use client";

import { ChevronDown } from "lucide-react";
import { useState } from "react";

import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { useChecks } from "@/hooks/use-checks";
import { cn } from "@/lib/utils";

/**
 * The per-scan disabled-checks control (RF-19): the catalogue from `GET /api/checks`, each
 * row a native checkbox. The selected ids are sent as `disabled_checks`.
 */
export function DisabledChecksField({
  value,
  onChange,
}: {
  value: string[];
  onChange: (next: string[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const checks = useChecks();
  const selected = new Set(value);

  function toggle(id: string, checked: boolean) {
    const next = new Set(selected);
    if (checked) next.add(id);
    else next.delete(id);
    onChange([...next]);
  }

  return (
    <div className="rounded-md border">
      <Button
        type="button"
        variant="ghost"
        className="flex w-full items-center justify-between rounded-b-none"
        onClick={() => setOpen((prev) => !prev)}
        aria-expanded={open}
        aria-controls="disabled-checks-panel"
      >
        <span>Disabled checks{value.length > 0 ? ` (${value.length})` : ""}</span>
        <ChevronDown
          className={cn("size-4 transition-transform", open && "rotate-180")}
          aria-hidden
        />
      </Button>

      {open ? (
        <div id="disabled-checks-panel" className="max-h-64 space-y-1 overflow-y-auto border-t p-2">
          {checks.isLoading ? (
            <p className="text-muted-foreground p-2 text-sm">Loading checks…</p>
          ) : null}
          {checks.isError ? (
            <p className="text-destructive p-2 text-sm">Could not load the check catalogue.</p>
          ) : null}
          {checks.data?.map((check) => (
            <label
              key={check.id}
              className="hover:bg-accent flex items-center gap-3 rounded px-2 py-1.5 text-sm"
            >
              <input
                type="checkbox"
                className="size-4"
                checked={selected.has(check.id)}
                onChange={(event) => toggle(check.id, event.target.checked)}
              />
              <span className="font-mono text-xs">{check.id}</span>
              <span className="flex-1 truncate">{check.name}</span>
              <span className="text-muted-foreground text-xs">{check.category}</span>
              <SeverityBadge severity={check.default_severity} />
            </label>
          ))}
        </div>
      ) : null}
    </div>
  );
}
