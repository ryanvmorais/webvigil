import { AlertOctagon, AlertTriangle, Info, ShieldAlert, ShieldQuestion } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { SEVERITY_CLASS, SEVERITY_LABEL, isSeverityName, type SeverityName } from "@/lib/severity";

const ICON: Record<SeverityName, typeof Info> = {
  INFO: Info,
  LOW: ShieldQuestion,
  MEDIUM: ShieldAlert,
  HIGH: AlertTriangle,
  CRITICAL: AlertOctagon,
};

// Colour is never the only signal: every badge also carries an icon and the text label (RNF-05).
export function SeverityBadge({ severity }: { severity: string }) {
  const name = isSeverityName(severity) ? severity : "INFO";
  const Icon = ICON[name];
  return (
    <Badge variant="outline" className={cn("gap-1", SEVERITY_CLASS[name])}>
      <Icon className="size-3" aria-hidden />
      {SEVERITY_LABEL[name]}
    </Badge>
  );
}
