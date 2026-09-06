/** Severity/confidence presentation metadata. Order and names come from the engine. */

export const SEVERITY_NAMES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export type SeverityName = (typeof SEVERITY_NAMES)[number];

// Highest first — matches the API's finding order (spec 002 RF-13); the UI never re-sorts.
export const SEVERITY_DESC: SeverityName[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export const SEVERITY_LABEL: Record<SeverityName, string> = {
  INFO: "Info",
  LOW: "Low",
  MEDIUM: "Medium",
  HIGH: "High",
  CRITICAL: "Critical",
};

/** Tailwind text/border classes keyed by the `severity.*` token scale (globals.css). */
export const SEVERITY_CLASS: Record<SeverityName, string> = {
  INFO: "border-severity-info/40 text-severity-info",
  LOW: "border-severity-low/40 text-severity-low",
  MEDIUM: "border-severity-medium/40 text-severity-medium",
  HIGH: "border-severity-high/40 text-severity-high",
  CRITICAL: "border-severity-critical/50 text-severity-critical",
};

export function isSeverityName(value: string): value is SeverityName {
  return (SEVERITY_NAMES as readonly string[]).includes(value);
}

export const CONFIDENCE_LABEL: Record<string, string> = {
  LOW: "Low confidence",
  MEDIUM: "Medium confidence",
  HIGH: "High confidence",
};
