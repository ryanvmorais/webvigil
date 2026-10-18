"use client";

import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { api, errorMessage } from "@/lib/api";

/**
 * Inline HTML report preview (RF-28): fetch `?format=html&download=false`, render the bytes
 * in a fully sandboxed iframe via a blob URL, revoke it on close (ADR-7).
 *
 * Known limit, kept on purpose: once the focus is inside the report, Esc does not reach the page
 * and the dialog stays open (the "Close" button and a click outside still close it). `sandbox=""`
 * gives the frame an opaque origin, so the page cannot listen to keys typed there; the fixes
 * (`allow-same-origin`, or taking the frame out of the Tab order) trade away the isolation or
 * keyboard scrolling. See "Report preview and the keyboard" in docs/web-ui.md.
 */
export function ReportPreview({ scanId, disabled }: { scanId: number; disabled: boolean }) {
  const [open, setOpen] = useState(false);
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    let created: string | null = null;
    api
      .reportBlob(scanId)
      .then((blob) => {
        created = URL.createObjectURL(blob);
        setBlobUrl(created);
      })
      .catch((cause) => setError(errorMessage(cause, "Could not load the report.")));
    return () => {
      if (created) URL.revokeObjectURL(created);
    };
  }, [open, scanId]);

  // Reset on close (not in the effect) so re-opening starts from a clean slate.
  function handleOpenChange(next: boolean) {
    setOpen(next);
    if (!next) {
      setBlobUrl(null);
      setError(null);
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" disabled={disabled}>
          Preview report
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle>HTML report</DialogTitle>
          <DialogDescription className="sr-only">
            A preview of this scan&apos;s HTML report, isolated from the rest of the page.
          </DialogDescription>
        </DialogHeader>
        {error ? <p className="text-destructive text-sm">{error}</p> : null}
        {blobUrl ? (
          <iframe
            title="HTML report preview"
            sandbox=""
            src={blobUrl}
            className="h-[70vh] w-full rounded border"
          />
        ) : error ? null : (
          <p className="text-muted-foreground text-sm" role="status">
            Loading…
          </p>
        )}
      </DialogContent>
    </Dialog>
  );
}
