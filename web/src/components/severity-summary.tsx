import { cn } from "@/lib/utils";
import { SEVERITY_CLASS, SEVERITY_DESC, SEVERITY_LABEL } from "@/lib/severity";

/** Per-severity `counts` from the scan record as compact chips (RF-24). */
export function SeveritySummary({
  counts,
  className,
}: {
  counts: Record<string, number>;
  className?: string;
}) {
  const chips = SEVERITY_DESC.filter((name) => (counts[name] ?? 0) > 0);

  if (chips.length === 0) {
    return <span className={cn("text-muted-foreground text-xs", className)}>No findings</span>;
  }

  return (
    <ul className={cn("flex flex-wrap items-center gap-1.5", className)}>
      {chips.map((name) => (
        <li
          key={name}
          className={cn("rounded border px-1.5 py-0.5 text-xs font-medium", SEVERITY_CLASS[name])}
        >
          {counts[name]} {SEVERITY_LABEL[name].toLowerCase()}
        </li>
      ))}
    </ul>
  );
}
