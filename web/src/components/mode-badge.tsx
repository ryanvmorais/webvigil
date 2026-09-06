import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

/** `passive` / `active` scan mode. Active is visually distinct (RF-11, RF-17). */
export function ModeBadge({ mode }: { mode: string }) {
  const active = mode === "active";
  return (
    <Badge variant="outline" className={cn(active && "border-severity-high/50 text-severity-high")}>
      {active ? "Active" : "Passive"}
    </Badge>
  );
}
