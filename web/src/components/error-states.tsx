/**
 * The shared loading / empty / error placeholders — `FullPageSpinner`, `Empty`,
 * `LoadFailed` (with a retry), `NotFound`. Every page composes these instead of
 * rolling its own, so the states look and read the same everywhere.
 */
import { AlertTriangle, Loader2, SearchX } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/**
 * Centered spinner. `className` overrides the default `min-h-[50vh]`, for a caller that
 * lays it over content that already has its own height (the `(auth)` layout).
 */
export function FullPageSpinner({
  label = "Loading…",
  className,
}: {
  label?: string;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "text-muted-foreground flex min-h-[50vh] items-center justify-center",
        className,
      )}
      role="status"
      aria-live="polite"
    >
      <Loader2 className="mr-2 size-5 animate-spin" aria-hidden />
      {label}
    </div>
  );
}

/**
 * `heading` is the level of the title: `h1` when the placeholder is the whole page (nothing
 * else on it names the page), `h2` when it sits under a page that already has its `h1`.
 */
type HeadingLevel = "h1" | "h2";

function Panel({
  icon,
  title,
  heading = "h2",
  children,
}: {
  icon: ReactNode;
  title: string;
  heading?: HeadingLevel;
  children?: ReactNode;
}) {
  const Heading = heading;
  return (
    <div className="mx-auto flex max-w-md flex-col items-center gap-3 py-16 text-center">
      <div className="text-muted-foreground" aria-hidden>
        {icon}
      </div>
      <Heading className="text-lg font-semibold">{title}</Heading>
      {children}
    </div>
  );
}

/** A "not found" page: it is always the whole page, so its title is the `h1`. */
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
    <Panel icon={<SearchX className="size-8" />} title={title} heading="h1">
      <p className="text-muted-foreground text-sm">{message}</p>
      <Button asChild variant="outline">
        <Link href={backHref}>{backLabel}</Link>
      </Button>
    </Panel>
  );
}

export function LoadFailed({
  message = "Could not load this page.",
  onRetry,
  heading,
}: {
  message?: string;
  onRetry?: () => void;
  heading?: HeadingLevel;
}) {
  return (
    <Panel
      icon={<AlertTriangle className="size-8" />}
      title="Something went wrong"
      heading={heading}
    >
      <p className="text-muted-foreground text-sm">{message}</p>
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
      {message ? <p className="text-muted-foreground text-sm">{message}</p> : null}
      {action}
    </Panel>
  );
}
