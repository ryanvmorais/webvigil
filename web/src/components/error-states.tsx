import { AlertTriangle, Loader2, SearchX } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { Button } from "@/components/ui/button";

export function FullPageSpinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div
      className="flex min-h-[50vh] items-center justify-center text-muted-foreground"
      role="status"
      aria-live="polite"
    >
      <Loader2 className="mr-2 size-5 animate-spin" aria-hidden />
      {label}
    </div>
  );
}

function Panel({
  icon,
  title,
  children,
}: {
  icon: ReactNode;
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="mx-auto flex max-w-md flex-col items-center gap-3 py-16 text-center">
      <div className="text-muted-foreground" aria-hidden>
        {icon}
      </div>
      <h2 className="text-lg font-semibold">{title}</h2>
      {children}
    </div>
  );
}

export function NotFound({
  title = "Not found",
  message = "That page or resource does not exist.",
  backHref = "/scans",
  backLabel = "Back to scans",
}: {
  title?: string;
  message?: string;
  backHref?: string;
  backLabel?: string;
}) {
  return (
    <Panel icon={<SearchX className="size-8" />} title={title}>
      <p className="text-sm text-muted-foreground">{message}</p>
      <Button asChild variant="outline">
        <Link href={backHref}>{backLabel}</Link>
      </Button>
    </Panel>
  );
}

export function LoadFailed({
  message = "Could not load this page.",
  onRetry,
}: {
  message?: string;
  onRetry?: () => void;
}) {
  return (
    <Panel icon={<AlertTriangle className="size-8" />} title="Something went wrong">
      <p className="text-sm text-muted-foreground">{message}</p>
      {onRetry ? <Button onClick={onRetry}>Retry</Button> : null}
    </Panel>
  );
}

export function Empty({
  title,
  message,
  action,
}: {
  title: string;
  message?: string;
  action?: ReactNode;
}) {
  return (
    <Panel icon={<SearchX className="size-8" />} title={title}>
      {message ? <p className="text-sm text-muted-foreground">{message}</p> : null}
      {action}
    </Panel>
  );
}
