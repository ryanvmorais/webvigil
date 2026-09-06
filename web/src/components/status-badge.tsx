import {
  Ban,
  CheckCircle2,
  CircleDashed,
  Loader2,
  PlugZap,
  XCircle,
  type LucideIcon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

type Meta = { label: string; icon: LucideIcon; className: string; spin?: boolean };

const STATUS: Record<string, Meta> = {
  queued: { label: "Queued", icon: CircleDashed, className: "text-muted-foreground" },
  running: { label: "Running", icon: Loader2, className: "text-severity-low", spin: true },
  completed: { label: "Completed", icon: CheckCircle2, className: "text-emerald-600" },
  failed: { label: "Failed", icon: XCircle, className: "text-severity-critical" },
  cancelled: { label: "Cancelled", icon: Ban, className: "text-muted-foreground" },
  interrupted: { label: "Interrupted", icon: PlugZap, className: "text-severity-medium" },
};

export function statusLabel(status: string): string {
  return STATUS[status]?.label ?? status;
}

export function StatusBadge({ status }: { status: string }) {
  const meta = STATUS[status] ?? {
    label: status,
    icon: CircleDashed,
    className: "text-muted-foreground",
  };
  const Icon = meta.icon;
  return (
    <Badge variant="outline" className={cn("gap-1", meta.className)}>
      <Icon className={cn("size-3", meta.spin && "animate-spin")} aria-hidden />
      {meta.label}
    </Badge>
  );
}
