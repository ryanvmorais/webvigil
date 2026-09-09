"use client";

import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { api, errorMessage } from "@/lib/api";

/**
 * Inline HTML report preview (RF-28): fetch `?format=html&download=false`, render the bytes
 * in a fully sandboxed iframe via a blob URL, revoke it on close (ADR-7).
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
          <p className="text-muted-foreground text-sm">Loading…</p>
        )}
      </DialogContent>
    </Dialog>
  );
}
