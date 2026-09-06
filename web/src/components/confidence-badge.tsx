import { CONFIDENCE_LABEL } from "@/lib/severity";

export function ConfidenceBadge({ confidence }: { confidence: string }) {
  const label = CONFIDENCE_LABEL[confidence] ?? `${confidence} confidence`;
  return <span className="text-xs text-muted-foreground">{label}</span>;
}
